using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Helpers;
using Sentinel.AspNetCore.Options;

namespace Sentinel.AspNetCore.Middleware;

/// <summary>
///     High-performance, secure, Native AOT-compatible mTLS binding middleware with cryptographic caching.
/// </summary>
internal sealed class MtlsBindingMiddleware
{
    private const int MaxCacheSize = 25000;
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private static readonly ConcurrentDictionary<string, CacheEntry> VerifiedCertCache = new(StringComparer.Ordinal);
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
    private readonly ILogger<MtlsBindingMiddleware> _logger;
    private readonly RequestDelegate _next;
    private readonly MtlsBindingOptions _options;
    private readonly IPNetworkMatcher _proxyMatcher;

    public MtlsBindingMiddleware(
        RequestDelegate next,
        ILogger<MtlsBindingMiddleware> logger,
        IOptions<MtlsBindingOptions> options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _proxyMatcher = new IPNetworkMatcher(_options.TrustedProxies);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var expectedThumbprint = TryResolveExpectedThumbprint(context, _logger);
        if (string.IsNullOrWhiteSpace(expectedThumbprint))
        {
            await _next(context);
            return;
        }

        try
        {
            var remoteIp = context.Connection.RemoteIpAddress;
            var isFromTrustedProxy = remoteIp is not null && _proxyMatcher.IsTrusted(remoteIp);

            if (isFromTrustedProxy)
            {
                var rawCertData = ExtractRawCertFromHeaders(context, _options.CertificateHeaders);
                if (rawCertData is null)
                {
                    _logger.LogWarning("mTLS error: Trusted proxy did not forward certificate header. RemoteIP: {IP}",
                        remoteIp?.ToString() ?? "unknown");
                    await Reject(context, "Missing required client certificate for mTLS binding.");
                    return;
                }

                var cacheKey = GenerateZeroAllocationCacheKey(rawCertData);

                if (VerifiedCertCache.TryGetValue(cacheKey, out var cachedEntry) &&
                    cachedEntry.ExpiresAt > DateTimeOffset.UtcNow)
                {
                    if (FixedTimeThumbprintEquals(expectedThumbprint, cachedEntry.Thumbprint))
                    {
                        await _next(context);
                        return;
                    }

                    await Reject(context, "Certificate thumbprint mismatch (cached).");
                    return;
                }

                using var proxyCert = rawCertData.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)
                    ? X509Certificate2.CreateFromPem(rawCertData)
                    : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(rawCertData));
                if (_options.ValidateChain && !ValidateCertificateChain(proxyCert, _logger))
                {
                    await Reject(context, "Provided certificate failed chain validation or is revoked (OCSP/CRL).");
                    return;
                }

                var hashBytes = SHA256.HashData(proxyCert.RawData);
                var actualThumbprint = Base64UrlEncoder.Encode(hashBytes);

                if (VerifiedCertCache.Count < MaxCacheSize)
                {
                    var expiresAt = DateTimeOffset.UtcNow.Add(CacheTtl);
                    VerifiedCertCache[cacheKey] = new CacheEntry(actualThumbprint, expiresAt);
                }

                if (!FixedTimeThumbprintEquals(expectedThumbprint, actualThumbprint))
                {
                    await Reject(context, "Certificate thumbprint mismatch.");
                    return;
                }
            }
            else if (_options.AllowDirectConnection)
            {
                var clientCertificate = await context.Connection.GetClientCertificateAsync();

                if (clientCertificate is null)
                {
                    _logger.LogWarning("mTLS error: Direct client certificate not found. RemoteIP: {IP}",
                        remoteIp?.ToString() ?? "unknown");
                    await Reject(context, "Missing required client certificate for mTLS binding.");
                    return;
                }

                if (_options.ValidateChain && !ValidateCertificateChain(clientCertificate, _logger))
                {
                    await Reject(context, "Client certificate failed chain validation.");
                    return;
                }

                var hashBytes = SHA256.HashData(clientCertificate.RawData);
                var actualThumbprint = Base64UrlEncoder.Encode(hashBytes);

                if (!FixedTimeThumbprintEquals(expectedThumbprint, actualThumbprint))
                {
                    _logger.LogWarning("mTLS error: Direct client certificate thumbprint mismatch. RemoteIP: {IP}",
                        remoteIp?.ToString() ?? "unknown");
                    await Reject(context, "Certificate thumbprint mismatch.");
                    return;
                }
            }
            else
            {
                _logger.LogWarning(
                    "mTLS error: Direct connections are disabled, but request arrived directly. RemoteIP: {IP}",
                    remoteIp?.ToString() ?? "unknown");
                await Reject(context, "Missing required client certificate for mTLS binding.");
                return;
            }

            await _next(context);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Cryptographic error during mTLS validation process.");
            await Reject(context, "Provided certificate is malformed or invalid.");
        }
    }

    private static bool ValidateCertificateChain(X509Certificate2 certificate, ILogger logger)
    {
        using var chain = new X509Chain();

        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);

        var isValid = chain.Build(certificate);
        if (!isValid)
        {
            foreach (var status in chain.ChainStatus)
            {
                logger.LogWarning("Certificate chain validation failure: {StatusInfo}", status.StatusInformation);
            }
        }

        return isValid;
    }

    private static bool FixedTimeThumbprintEquals(string expected, string actual)
    {
        Span<byte> expectedBytes = stackalloc byte[128];
        Span<byte> actualBytes = stackalloc byte[128];

        var expectedLen = Encoding.UTF8.GetBytes(expected.AsSpan(), expectedBytes);
        var actualLen = Encoding.UTF8.GetBytes(actual.AsSpan(), actualBytes);

        if (expectedLen != actualLen)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            expectedBytes[..expectedLen],
            actualBytes[..actualLen]);
    }

    private static string GenerateZeroAllocationCacheKey(string rawCertData)
    {
        var requiredBytes = Encoding.UTF8.GetByteCount(rawCertData);
        byte[]? rentedBuffer = null;

        var utf8Bytes = requiredBytes <= 4096
            ? stackalloc byte[4096]
            : rentedBuffer = ArrayPool<byte>.Shared.Rent(requiredBytes);

        try
        {
            var written = Encoding.UTF8.GetBytes(rawCertData.AsSpan(), utf8Bytes);
            Span<byte> hashBytes = stackalloc byte[32];
            SHA256.HashData(utf8Bytes[..written], hashBytes);

            return Base64UrlEncoder.Encode(hashBytes.ToArray());
        }
        finally
        {
            if (rentedBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
        }
    }

    private static string? ExtractRawCertFromHeaders(HttpContext context, string[] headers)
    {
        foreach (var t in headers)
        {
            if (context.Request.Headers.TryGetValue(t, out var value) &&
                !string.IsNullOrEmpty(value.ToString()))
            {
                var rawHeader = value.ToString();

                return rawHeader.Contains('%', StringComparison.Ordinal)
                    ? Uri.UnescapeDataString(rawHeader)
                    : rawHeader;
            }
        }

        return null;
    }

    private static string? TryResolveExpectedThumbprint(HttpContext context, ILogger logger)
    {
        if (TryGetThumbprintFromAuthenticatedPrincipal(context, logger, out var thumbprintFromPrincipal))
        {
            return thumbprintFromPrincipal;
        }

        return TryGetThumbprintFromAccessToken(context, logger);
    }

    private static bool TryGetThumbprintFromAuthenticatedPrincipal(
        HttpContext context,
        ILogger logger,
        out string? thumbprint)
    {
        thumbprint = null;

        if (context.User.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var cnfClaimValue = context.User.FindFirst("cnf")?.Value;
        if (string.IsNullOrWhiteSpace(cnfClaimValue))
        {
            return false;
        }

        thumbprint = TryParseThumbprint(cnfClaimValue, logger, context.User.FindFirst("sub")?.Value);
        return true;
    }

    private static string? TryGetThumbprintFromAccessToken(HttpContext context, ILogger logger)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return null;
        }

        string token;
        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["DPoP ".Length..].Trim();
        }
        else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["Bearer ".Length..].Trim();
        }
        else
        {
            return null;
        }

        if (!TokenHandler.CanReadToken(token))
        {
            return null;
        }

        try
        {
            var jwt = TokenHandler.ReadJsonWebToken(token);
            if (!jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnfElement) ||
                cnfElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return cnfElement.TryGetProperty("x5t#S256", out var thumbprintElement)
                ? thumbprintElement.GetString()
                : null;
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException)
        {
            logger.LogWarning("Error reading cnf claim from token.");
            return null;
        }
    }

    private static string? TryParseThumbprint(string cnfClaimValue, ILogger logger, string? subject)
    {
        try
        {
            using var doc = JsonDocument.Parse(cnfClaimValue);
            if (!doc.RootElement.TryGetProperty("x5t#S256", out var thumbprintElement))
            {
                return null;
            }

            return thumbprintElement.GetString();
        }
        catch (JsonException)
        {
            logger.LogWarning("Invalid cnf claim JSON for subject {Subject}.", subject);
            return null;
        }
    }

    private static async Task Reject(HttpContext context, string detail)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/problem+json; charset=utf-8";

        var problem = new ProblemDetails
        {
            Type = "/errors/mtls-binding-failed",
            Title = "Certificate Binding Error",
            Detail = detail,
            Status = StatusCodes.Status403Forbidden,
            Instance = context.Request.Path
        };

        var json = JsonSerializer.Serialize(problem, AspNetCoreJsonContext.Default.ProblemDetails);
        await context.Response.WriteAsync(json);
    }

    private sealed record CacheEntry(string Thumbprint, DateTimeOffset ExpiresAt);
}
