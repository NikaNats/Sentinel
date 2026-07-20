using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Stores;
using Sentinel.DPoP.Pqc;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Diagnostics;
using IDpopProofValidator = Sentinel.Security.Abstractions.DPoP.IDpopProofValidator;
using MlDsaSecurityKey = Sentinel.Security.Abstractions.Pqc.MlDsaSecurityKey;

namespace Sentinel.AspNetCore.Middleware;

/// <summary>
///     Validates DPoP proofs per RFC 9449 with support for classical (EC/RSA)
///     and post-quantum (ML-DSA) key types. Implements nonce rotation,
///     L1 anti-flood protection, and constant-time failure responses.
/// </summary>
internal sealed class DpopValidationMiddleware
{
    private const long TargetFailureFloorMs = 100;
    private const string DpopSchemePrefix = "DPoP ";
    private const string BearerSchemePrefix = "Bearer ";
    private const string DpopTypValue = "dpop+jwt";
    private const string DpopJktItemKey = "dpop.jkt";
    private const string DpopNonceHeader = "DPoP-Nonce";

    private static readonly JsonWebTokenHandler TokenHandler = new();

    // Structured logging delegates to completely eliminate string allocations on hot paths
    private static readonly Action<ILogger, string, Exception?> LogSignatureError =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2001, "DpopSignatureError"),
            "DPoP Signature Error: {Message}");

    private static readonly Action<ILogger, string, Exception?> LogAttackBlocked =
        LoggerMessage.Define<string>(LogLevel.Critical, new EventId(2002, "DpopAttackBlocked"),
            "SECURITY ALERT: {Reason}");

    private readonly HashSet<string> _allowedAlgorithms;
    private readonly L1AntiFloodCache _l1AntiFloodCache;
    private readonly ILogger<DpopValidationMiddleware> _logger;

    private readonly RequestDelegate _next;
    private readonly TimeSpan _nonceTtl;
    private readonly PqcCryptoProviderFactory? _pqcFactory;
    private readonly string _supportedAlgsHeaderValue;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;

    public DpopValidationMiddleware(
        RequestDelegate next,
        IDpopThumbprintComputer thumbprintComputer,
        TimeProvider timeProvider,
        L1AntiFloodCache l1AntiFloodCache,
        ILogger<DpopValidationMiddleware> logger,
        IOptions<DPoPOptions> dpopOptions,
        PqcCryptoProviderFactory? pqcFactory = null)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _thumbprintComputer = thumbprintComputer ?? throw new ArgumentNullException(nameof(thumbprintComputer));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _l1AntiFloodCache = l1AntiFloodCache ?? throw new ArgumentNullException(nameof(l1AntiFloodCache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pqcFactory = pqcFactory;

        var options = dpopOptions?.Value ?? throw new ArgumentNullException(nameof(dpopOptions));
        _allowedAlgorithms = new HashSet<string>(options.AllowedAlgorithms, StringComparer.OrdinalIgnoreCase);
        _nonceTtl = TimeSpan.FromMinutes(5);
        _supportedAlgsHeaderValue = string.Join(' ', options.AllowedAlgorithms);
    }

    public async Task InvokeAsync(
        HttpContext context,
        IDpopProofValidator validator,
        IDpopNonceStore nonceStore)
    {
        var startTimestamp = _timeProvider.GetTimestamp();

        // Optimized allocation-free initial verification of the Authorization header
        var authValues = context.Request.Headers.Authorization;
        if (authValues.Count == 0)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var authHeader = authValues[0];
        if (string.IsNullOrEmpty(authHeader))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Isolate the ReadOnlySpan in a synchronous helper to prevent state-machine lifting errors (CS4007)
        if (!TryValidateAuthHeader(authHeader, out var isBearerDowngrade, out var accessToken))
        {
            if (isBearerDowngrade)
            {
                await EnforceConstantTimeFailureAsync(startTimestamp, context, "bearer_downgrade_attempt")
                    .ConfigureAwait(false);
                return;
            }

            await _next(context).ConfigureAwait(false);
            return;
        }

        var dpopHeaderValues = context.Request.Headers["DPoP"];
        if (dpopHeaderValues.Count == 0)
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "missing_dpop_proof")
                .ConfigureAwait(false);
            return;
        }

        var dpopProofString = dpopHeaderValues[0];
        if (string.IsNullOrWhiteSpace(dpopProofString))
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "missing_dpop_proof")
                .ConfigureAwait(false);
            return;
        }

        // Single-pass parsing: extract and validate properties directly from the JWT's JsonElement representation
        if (!TryExtractProofDetails(dpopProofString, out var token, out var jwkElement, out var thumbprint))
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "malformed_dpop_proof")
                .ConfigureAwait(false);
            return;
        }

        if (_l1AntiFloodCache.IsTemporarilyBlacklisted(thumbprint))
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "l1_anti_flood_blocked")
                .ConfigureAwait(false);
            return;
        }

        if (!await ValidateDpopSignatureAsync(context, token, dpopProofString, jwkElement, context.RequestAborted)
                .ConfigureAwait(false))
        {
            _l1AntiFloodCache.RecordFailedAttempt(thumbprint);
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "invalid_signature")
                .ConfigureAwait(false);
            return;
        }

        var requestUrl = UriHelper.BuildAbsolute(
            context.Request.Scheme,
            context.Request.Host,
            context.Request.PathBase,
            context.Request.Path);

        var expectedNonce = await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted).ConfigureAwait(false);

        var validationRequest = new DpopValidationRequest(
            dpopProofString,
            context.Request.Method,
            new Uri(requestUrl, UriKind.Absolute),
            accessToken,
            expectedNonce);

        var validationResult =
            await validator.ValidateAsync(validationRequest, context.RequestAborted).ConfigureAwait(false);
        var result = validationResult.ToHttpResult();

        if (!result.IsValid)
        {
            _l1AntiFloodCache.RecordFailedAttempt(thumbprint);

            if (string.Equals(result.Error, "use_dpop_nonce", StringComparison.Ordinal))
            {
                var challengeNonce = GenerateNonce();
                var stored = await nonceStore
                    .TryStoreNonceAsync(thumbprint, challengeNonce, _nonceTtl, context.RequestAborted)
                    .ConfigureAwait(false);

                var effectiveNonce = stored
                    ? challengeNonce
                    : await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted).ConfigureAwait(false) ??
                      challengeNonce;

                context.Response.Headers.Append(DpopNonceHeader, effectiveNonce);
            }

            await EnforceConstantTimeFailureAsync(startTimestamp, context, result.Error ?? "invalid_dpop_proof")
                .ConfigureAwait(false);
            return;
        }

        // Atomic consumption flow to eliminate TOCTOU race conditions under load
        if (expectedNonce is not null)
        {
            var wasConsumed = await nonceStore
                .ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, context.RequestAborted)
                .ConfigureAwait(false);

            if (!wasConsumed)
            {
                var retryNonce = GenerateNonce();
                await nonceStore
                    .TryStoreNonceAsync(thumbprint, retryNonce, _nonceTtl, context.RequestAborted)
                    .ConfigureAwait(false);
                context.Response.Headers.Append(DpopNonceHeader, retryNonce);

                await EnforceConstantTimeFailureAsync(startTimestamp, context, "use_dpop_nonce").ConfigureAwait(false);
                return;
            }
        }

        context.Items[DpopJktItemKey] = thumbprint;

        if (result.NewNonce is not null)
        {
            var rotationState = new NonceRotationState(context, nonceStore, thumbprint, result.NewNonce, _nonceTtl);

            context.Response.OnStarting(static async state =>
            {
                var s = (NonceRotationState)state;

                if (s.HttpContext.Response.StatusCode is < 200 or >= 400)
                {
                    return;
                }

                try
                {
                    var stored = await s.NonceStore
                        .TryStoreNonceAsync(s.Thumbprint, s.NewNonce, s.NonceTtl, s.HttpContext.RequestAborted)
                        .ConfigureAwait(false);

                    var nonceToEmit = stored
                        ? s.NewNonce
                        : await s.NonceStore
                            .GetNonceAsync(s.Thumbprint, s.HttpContext.RequestAborted)
                            .ConfigureAwait(false) ?? s.NewNonce;

                    s.HttpContext.Response.Headers.Append(DpopNonceHeader, nonceToEmit);
                }
                catch (OperationCanceledException)
                {
                }
            }, rotationState);
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    ///     Synchronous stack isolation helper to keep Ref Structs (ReadOnlySpan) out of the async state machine.
    /// </summary>
    private static bool TryValidateAuthHeader(
        string authHeader,
        out bool isBearerDowngrade,
        [NotNullWhen(true)] out string? accessToken)
    {
        isBearerDowngrade = false;
        accessToken = null;

        var span = authHeader.AsSpan();

        if (span.StartsWith(DpopSchemePrefix, StringComparison.OrdinalIgnoreCase))
        {
            accessToken = authHeader.Substring(DpopSchemePrefix.Length).Trim();
            return true;
        }

        if (span.StartsWith(BearerSchemePrefix, StringComparison.OrdinalIgnoreCase))
        {
            var bearerPayload = span[BearerSchemePrefix.Length..].Trim();
            if (!bearerPayload.Contains('~'))
            {
                isBearerDowngrade = true;
            }
        }

        return false;
    }

    private bool TryExtractProofDetails(
        string dpopHeader,
        [NotNullWhen(true)] out JsonWebToken? token,
        out JsonElement jwkElement,
        [NotNullWhen(true)] out string? thumbprint)
    {
        token = null;
        jwkElement = default;
        thumbprint = null;

        try
        {
            if (!TokenHandler.CanReadToken(dpopHeader))
            {
                return false;
            }

            token = TokenHandler.ReadJsonWebToken(dpopHeader);
            if (!token.TryGetHeaderValue("jwk", out jwkElement))
            {
                return false;
            }

            // Direct calculation on the parsed JsonElement payload to avoid manual parsing string allocation cycles
            thumbprint = _thumbprintComputer.Compute(jwkElement);
            return !string.IsNullOrWhiteSpace(thumbprint);
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException or JsonException)
        {
            return false;
        }
    }

    private async Task<bool> ValidateDpopSignatureAsync(
        HttpContext context,
        JsonWebToken token,
        string dpopHeader,
        JsonElement jwkElement,
        CancellationToken cancellationToken)
    {
        try
        {
            var algorithm = token.Alg;
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                return false;
            }

            if (!_allowedAlgorithms.Contains(algorithm))
            {
                LogSignatureError(_logger, $"Rejecting unsupported algorithm: {algorithm}", null);
                return false;
            }

            if (!string.Equals(token.Typ, DpopTypValue, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (jwkElement.TryGetProperty("kty", out var ktyProp))
            {
                var kty = ktyProp.GetString();
                if (string.Equals(kty, "oct", StringComparison.OrdinalIgnoreCase))
                {
                    LogAttackBlocked(_logger, "Symmetric oct-key confusion attempt detected.", null);
                    return false;
                }
            }

            if (jwkElement.TryGetProperty("d", out _))
            {
                LogAttackBlocked(_logger, "Public JWK header contains private key material.", null);
                return false;
            }

            SecurityKey signingKey;
            var ktyValue = jwkElement.TryGetProperty("kty", out var kv) ? kv.GetString() : null;

            if (string.Equals(ktyValue, "ML-DSA", StringComparison.Ordinal))
            {
                if (!jwkElement.TryGetProperty("x", out var xProp))
                {
                    return false;
                }

                var xStr = xProp.GetString();
                if (string.IsNullOrWhiteSpace(xStr))
                {
                    return false;
                }

                byte[] publicKeyBytes;
                try
                {
                    publicKeyBytes = Base64UrlEncoder.DecodeBytes(xStr);
                }
                catch (FormatException ex)
                {
                    LogSignatureError(_logger, "Malformed Base64Url in ML-DSA JWK 'x' parameter.", ex);
                    return false;
                }

                signingKey = new MlDsaSecurityKey(publicKeyBytes, algorithm);
            }
            else
            {
                var jwkJson = jwkElement.GetRawText();
                signingKey = JsonWebKey.Create(jwkJson);
            }

            var activeFactory = _pqcFactory ?? context.RequestServices.GetService<PqcCryptoProviderFactory>();
            if (activeFactory is null)
            {
                var verifier = context.RequestServices.GetService<IMlDsaSignatureVerifier>();
                if (verifier is not null)
                {
                    activeFactory = new PqcCryptoProviderFactory(verifier);
                }
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                CryptoProviderFactory = activeFactory,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireSignedTokens = true,
                ValidAlgorithms = [algorithm],
                ValidateLifetime = false,
                RequireExpirationTime = false
            };

            var result = await TokenHandler
                .ValidateTokenAsync(dpopHeader, validationParameters)
                .ConfigureAwait(false);

            return result.IsValid;
        }
        catch (Exception ex) when (ex is ArgumentException
                                       or SecurityTokenException
                                       or JsonException
                                       or CryptographicException
                                       or FormatException
                                       or InvalidOperationException)
        {
            _logger.LogDebug(ex, "DPoP signature validation failed with exception.");
            return false;
        }
    }

    private async Task EnforceConstantTimeFailureAsync(
        long startTimestamp, HttpContext context, string reason)
    {
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", reason));

        var algsSegment = $"algs=\"{_supportedAlgsHeaderValue}\"";

        var wwwAuth = reason switch
        {
            "use_dpop_nonce" => $"DPoP error=\"use_dpop_nonce\", {algsSegment}",
            "missing_dpop_proof" => "DPoP error=\"missing_dpop_proof\"",
            _ => $"DPoP error=\"invalid_dpop_proof\", {algsSegment}"
        };

        context.Response.Headers.Append("WWW-Authenticate", wwwAuth);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/problem+json; charset=utf-8";

        var jitterMs = RandomNumberGenerator.GetInt32(0, 16);
        var targetDuration = TimeSpan.FromMilliseconds(TargetFailureFloorMs + jitterMs);
        var elapsed = _timeProvider.GetElapsedTime(startTimestamp);
        var remaining = targetDuration - elapsed;

        if (remaining > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(remaining, _timeProvider, context.RequestAborted)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }

        if (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }

        var problem = new ProblemDetails
        {
            Type = "/errors/invalid-dpop-proof",
            Title = "DPoP proof validation failed",
            Status = StatusCodes.Status401Unauthorized,
            Detail = string.Equals(reason, "use_dpop_nonce", StringComparison.OrdinalIgnoreCase)
                ? "A new DPoP nonce is required."
                : "The provided DPoP proof is missing or invalid.",
            Instance = context.Request.Path
        };

        try
        {
            var json = JsonSerializer.Serialize(problem, AspNetCoreJsonContext.Default.ProblemDetails);
            await context.Response.WriteAsync(json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static string GenerateNonce()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64Url.EncodeToString(bytes);
    }

    private sealed record NonceRotationState(
        HttpContext HttpContext,
        IDpopNonceStore NonceStore,
        string Thumbprint,
        string NewNonce,
        TimeSpan NonceTtl);
}
