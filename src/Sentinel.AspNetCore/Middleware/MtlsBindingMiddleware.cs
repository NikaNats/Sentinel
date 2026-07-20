using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sentinel.AspNetCore.Helpers;
using Sentinel.AspNetCore.Options;
using Sentinel.AspNetCore.Stores;

namespace Sentinel.AspNetCore.Middleware;

/// <summary>
///     Enforces Mutual TLS (mTLS) Client Certificate-Bound Access Tokens per RFC 8705.
///     Validates that the client certificate matches the thumbprint in the authenticated principal's cnf claim.
/// </summary>
internal sealed class MtlsBindingMiddleware
{
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2"; // Client Authentication EKU

    // Structured logging delegates for zero-allocation logging on hot paths
    private static readonly Action<ILogger, string, Exception?> LogMtlsWarning =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(3001, "MtlsWarning"), "mTLS warning: {Reason}");

    private static readonly Action<ILogger, string, string?, Exception?> LogProxyError =
        LoggerMessage.Define<string, string?>(LogLevel.Warning, new EventId(3002, "MtlsProxyError"),
            "mTLS error: {Reason}. RemoteIP: {IP}");

    private static readonly Action<ILogger, Exception?> LogCryptoError =
        LoggerMessage.Define(LogLevel.Error, new EventId(3003, "MtlsCryptoError"),
            "Cryptographic or format error during mTLS validation process.");

    private readonly MtlsCertificateCache _certCache;
    private readonly ILogger<MtlsBindingMiddleware> _logger;

    private readonly RequestDelegate _next;
    private readonly MtlsBindingOptions _options;
    private readonly IPNetworkMatcher _proxyMatcher;

    public MtlsBindingMiddleware(
        RequestDelegate next,
        ILogger<MtlsBindingMiddleware> logger,
        IOptions<MtlsBindingOptions> options,
        MtlsCertificateCache certCache)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _certCache = certCache ?? throw new ArgumentNullException(nameof(certCache));
        _proxyMatcher = new IPNetworkMatcher(_options.TrustedProxies);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var identity = context.User.Identity;
        if (identity == null || !identity.IsAuthenticated)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // 1. High-Performance Bypass: If the token is bound via DPoP instead of mTLS, pass through immediately.
        // This prevents DPoP tokens from being blocked by subsequent mTLS-binding checks.
        if (IsDpopBoundToken(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // 2. Expected thumbprint MUST be extracted exclusively from the authenticated user claims
        // If the token is not DPoP-bound and lacks an mTLS cnf claim, reject immediately (Scenario 10 Fail-Closed).
        if (!TryGetThumbprintFromAuthenticatedPrincipal(context, out var expectedThumbprint))
        {
            LogMtlsWarning(_logger,
                "Authenticated request is missing the required 'cnf' claim or has invalid structure.", null);
            await Reject(context, "Missing required certificate confirmation (cnf) claim.").ConfigureAwait(false);
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
                    LogProxyError(_logger, "Trusted proxy did not forward certificate header", remoteIp?.ToString(),
                        null);
                    await Reject(context, "Missing required client certificate for mTLS binding.")
                        .ConfigureAwait(false);
                    return;
                }

                // Optimization: Pre-allocate the cache key using string.Concat to avoid string interpolation allocations
                var cacheKey = string.Concat("mtls:", GenerateZeroAllocationCacheKey(rawCertData));

                if (_certCache.TryGetValue(cacheKey, out var cachedThumbprint))
                {
                    if (FixedTimeThumbprintEquals(expectedThumbprint, cachedThumbprint!))
                    {
                        await _next(context).ConfigureAwait(false);
                        return;
                    }

                    await Reject(context, "Certificate thumbprint mismatch (cached).").ConfigureAwait(false);
                    return;
                }

                using var proxyCert = LoadCertificateFromRawData(rawCertData);

                var hashBytes = SHA256.HashData(proxyCert.RawData);
                var actualThumbprint = Base64Url.EncodeToString(hashBytes);

                if (!FixedTimeThumbprintEquals(expectedThumbprint, actualThumbprint))
                {
                    LogProxyError(_logger,
                        $"Client certificate thumbprint mismatch. Expected: {expectedThumbprint}, Got: {actualThumbprint}",
                        remoteIp?.ToString(), null);
                    await Reject(context, "Certificate thumbprint mismatch.").ConfigureAwait(false);
                    return;
                }

                if (_options.ValidateChain)
                {
                    var isValidChain = await Task.Run(() => ValidateCertificateChain(proxyCert), context.RequestAborted)
                        .ConfigureAwait(false);
                    if (!isValidChain)
                    {
                        await Reject(context, "Provided certificate failed chain validation or is revoked.")
                            .ConfigureAwait(false);
                        return;
                    }
                }

                _certCache.Set(cacheKey, actualThumbprint, TimeSpan.FromMinutes(5));
            }
            else if (_options.AllowDirectConnection)
            {
                using var clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted)
                    .ConfigureAwait(false);

                if (clientCertificate is null)
                {
                    LogProxyError(_logger, "Direct client certificate not found", remoteIp?.ToString(), null);
                    await Reject(context, "Missing required client certificate for mTLS binding.")
                        .ConfigureAwait(false);
                    return;
                }

                var hashBytes = SHA256.HashData(clientCertificate.RawData);
                var actualThumbprint = Base64Url.EncodeToString(hashBytes);

                if (!FixedTimeThumbprintEquals(expectedThumbprint, actualThumbprint))
                {
                    LogProxyError(_logger, "Direct client certificate thumbprint mismatch", remoteIp?.ToString(), null);
                    await Reject(context, "Certificate thumbprint mismatch.").ConfigureAwait(false);
                    return;
                }

                var validationCacheKey = string.Concat("mtls-valid:", actualThumbprint);
                if (_options.ValidateChain)
                {
                    if (!_certCache.TryGetValue(validationCacheKey, out _))
                    {
                        var isValidChain = await Task
                            .Run(() => ValidateCertificateChain(clientCertificate), context.RequestAborted)
                            .ConfigureAwait(false);
                        if (!isValidChain)
                        {
                            await Reject(context, "Client certificate failed chain validation.").ConfigureAwait(false);
                            return;
                        }

                        _certCache.Set(validationCacheKey, actualThumbprint, TimeSpan.FromMinutes(5));
                    }
                }
            }
            else
            {
                LogProxyError(_logger, "Direct connections are disabled", remoteIp?.ToString(), null);
                await Reject(context, "Missing required client certificate for mTLS binding.").ConfigureAwait(false);
                return;
            }

            await _next(context).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            LogCryptoError(_logger, ex);
            await Reject(context, "Provided certificate is malformed or invalid.").ConfigureAwait(false);
        }
    }

    private static X509Certificate2 LoadCertificateFromRawData(string rawCertData)
    {
        if (rawCertData.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            return X509Certificate2.CreateFromPem(rawCertData);
        }

        var maxDecodedLength = rawCertData.Length * 3 / 4;
        byte[]? rented = null;
        var decodedBuffer = maxDecodedLength <= 4096
            ? stackalloc byte[4096]
            : rented = ArrayPool<byte>.Shared.Rent(maxDecodedLength);

        try
        {
            if (Convert.TryFromBase64String(rawCertData, decodedBuffer, out var bytesWritten))
            {
                return X509CertificateLoader.LoadCertificate(decodedBuffer[..bytesWritten]);
            }

            throw new FormatException("The certificate data is not valid Base64.");
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private bool ValidateCertificateChain(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();

        chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);

        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthOid));

        var isValid = chain.Build(certificate);
        if (!isValid)
        {
            foreach (var status in chain.ChainStatus)
            {
                LogMtlsWarning(_logger, $"Certificate chain validation failure: {status.StatusInformation}", null);
            }
        }

        return isValid;
    }

    private static bool FixedTimeThumbprintEquals(string expected, string actual)
    {
        if (expected.Length > 128 || actual.Length > 128)
        {
            return false;
        }

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
            var written = Encoding.UTF8.GetBytes(rawCertData, utf8Bytes);
            Span<byte> hashBytes = stackalloc byte[32];
            SHA256.HashData(utf8Bytes[..written], hashBytes);

            return Base64Url.EncodeToString(hashBytes);
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
        for (var i = 0; i < headers.Length; i++)
        {
            var headerName = headers[i];
            if (context.Request.Headers.TryGetValue(headerName, out var values))
            {
                if (values.Count > 1)
                {
                    return null;
                }

                var rawHeader = values[0];
                if (!string.IsNullOrEmpty(rawHeader))
                {
                    return rawHeader.Contains('%', StringComparison.Ordinal)
                        ? Uri.UnescapeDataString(rawHeader)
                        : rawHeader;
                }
            }
        }

        return null;
    }

    private static bool IsDpopBoundToken(HttpContext context)
    {
        var cnfClaimValue = context.User.FindFirst("cnf")?.Value;
        if (string.IsNullOrWhiteSpace(cnfClaimValue))
        {
            return false;
        }

        var utf8Bytes = Encoding.UTF8.GetBytes(cnfClaimValue);
        var reader = new Utf8JsonReader(utf8Bytes);

        var hasJkt = false;
        var hasX5t = false;

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                var propertyName = reader.GetString();
                if (string.Equals(propertyName, "jti", StringComparison.Ordinal) ||
                    string.Equals(propertyName, "jkt", StringComparison.Ordinal))
                {
                    hasJkt = true;
                }
                else if (string.Equals(propertyName, "x5t#S256", StringComparison.Ordinal))
                {
                    hasX5t = true;
                }
            }
        }

        return hasJkt && !hasX5t;
    }

    private static bool TryGetThumbprintFromAuthenticatedPrincipal(
        HttpContext context,
        [NotNullWhen(true)] out string? thumbprint)
    {
        thumbprint = null;

        var cnfClaimValue = context.User.FindFirst("cnf")?.Value;
        if (string.IsNullOrWhiteSpace(cnfClaimValue))
        {
            return false;
        }

        var utf8Bytes = Encoding.UTF8.GetBytes(cnfClaimValue);
        var reader = new Utf8JsonReader(utf8Bytes);

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                var propertyName = reader.GetString();
                if (string.Equals(propertyName, "x5t#S256", StringComparison.Ordinal))
                {
                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                    {
                        thumbprint = reader.GetString();
                        return !string.IsNullOrWhiteSpace(thumbprint);
                    }
                }
            }
        }

        return false;
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
        await context.Response.WriteAsync(json, context.RequestAborted).ConfigureAwait(false);
    }
}
