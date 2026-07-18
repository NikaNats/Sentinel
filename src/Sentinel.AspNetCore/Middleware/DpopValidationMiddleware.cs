using System.Security.Cryptography;
using System.Text.Json;
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

internal sealed class DpopValidationMiddleware(
    RequestDelegate next,
    IDpopThumbprintComputer thumbprintComputer,
    TimeProvider timeProvider,
    L1AntiFloodCache l1AntiFloodCache,
    PqcCryptoProviderFactory? pqcFactory = null)
{
    private const long TargetFailureFloorMs = 100;
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);

    public async Task InvokeAsync(
        HttpContext context,
        IDpopProofValidator validator,
        IDpopNonceStore nonceStore,
        IOptions<DPoPOptions> dpopOptions)
    {
        var startTimestamp = timeProvider.GetTimestamp();

        var authHeaderString = context.Request.Headers.Authorization.ToString();
        var authHeaderSpan = authHeaderString.AsSpan();

        if (authHeaderSpan.IsEmpty || !authHeaderSpan.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            if (!authHeaderSpan.IsEmpty && authHeaderSpan.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var bearerTokenSpan = authHeaderSpan["Bearer ".Length..].Trim();
                if (bearerTokenSpan.Contains('~'))
                {
                    await next(context);
                    return;
                }

                await EnforceConstantTimeFailureAsync(startTimestamp, context, "bearer_downgrade_attempt");
                return;
            }

            await next(context);
            return;
        }

        var dpopProofString = context.Request.Headers.TryGetValue("DPoP", out var dpopVal)
            ? dpopVal.ToString()
            : string.Empty;

        if (string.IsNullOrWhiteSpace(dpopProofString))
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "missing_dpop_proof");
            return;
        }

        var token = authHeaderSpan["DPoP ".Length..].Trim().ToString();
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        var thumbprint = TryExtractProofThumbprint(dpopProofString, thumbprintComputer);

        if (!string.IsNullOrWhiteSpace(thumbprint) && l1AntiFloodCache.IsTemporarilyBlacklisted(thumbprint))
        {
            await EnforceConstantTimeFailureAsync(startTimestamp, context, "l1_anti_flood_blocked");
            return;
        }

        if (!await ValidateDpopSignatureOnlyAsync(context, dpopProofString, dpopOptions, context.RequestAborted))
        {
            if (!string.IsNullOrWhiteSpace(thumbprint))
            {
                l1AntiFloodCache.RecordFailedAttempt(thumbprint);
            }

            await EnforceConstantTimeFailureAsync(startTimestamp, context, "invalid_signature");
            return;
        }

        string? expectedNonce = null;
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            expectedNonce = await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted);
        }

        var validationRequest = new DpopValidationRequest(dpopProofString, context.Request.Method, new Uri(requestUrl),
            token, expectedNonce);
        var validationResult = await validator.ValidateAsync(validationRequest, context.RequestAborted);
        var result = validationResult.ToHttpResult();

        if (!result.IsValid)
        {
            if (!string.IsNullOrWhiteSpace(thumbprint))
            {
                l1AntiFloodCache.RecordFailedAttempt(thumbprint);
            }

            if (string.Equals(result.Error, "use_dpop_nonce", StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(thumbprint))
            {
                var challengeNonce = GenerateNonce();
                var stored =
                    await nonceStore.TryStoreNonceAsync(thumbprint, challengeNonce, NonceTtl, context.RequestAborted);
                var effectiveNonce = stored
                    ? challengeNonce
                    : await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted) ?? challengeNonce;

                context.Response.Headers.Append("DPoP-Nonce", effectiveNonce);
            }

            await EnforceConstantTimeFailureAsync(startTimestamp, context, result.Error ?? "invalid_dpop_proof");
            return;
        }


        if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(expectedNonce))
        {
            var wasConsumed = await nonceStore.ConsumeNonceIfMatchesAsync(
                thumbprint,
                expectedNonce,
                context.RequestAborted);

            if (!wasConsumed)
            {
                if (!string.IsNullOrWhiteSpace(thumbprint))
                {
                    l1AntiFloodCache.RecordFailedAttempt(thumbprint);
                }

                await EnforceConstantTimeFailureAsync(startTimestamp, context, "use_dpop_nonce");
                return;
            }
        }

        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            context.Items["dpop.jkt"] = thumbprint;
        }

        if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(result.NewNonce))
        {
            context.Response.OnStarting(static async state =>
            {
                var callbackState = (NonceRotationState)state;

                if (callbackState.HttpContext.Response.StatusCode is < 200 or >= 400)
                {
                    return;
                }

                try
                {
                    var stored = await callbackState.NonceStore.TryStoreNonceAsync(
                        callbackState.Thumbprint,
                        callbackState.NewNonce,
                        NonceTtl,
                        callbackState.HttpContext.RequestAborted);

                    var nonceToEmit = stored
                        ? callbackState.NewNonce
                        : await callbackState.NonceStore.GetNonceAsync(
                            callbackState.Thumbprint,
                            callbackState.HttpContext.RequestAborted) ?? callbackState.NewNonce;

                    callbackState.HttpContext.Response.Headers.Append("DPoP-Nonce", nonceToEmit);
                }
                catch (OperationCanceledException)
                {
                }
            }, new NonceRotationState(context, nonceStore, thumbprint, result.NewNonce));
        }

        await next(context);
    }

    private async Task<bool> ValidateDpopSignatureOnlyAsync(
        HttpContext context,
        string dpopHeader,
        IOptions<DPoPOptions> dpopOptions,
        CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(dpopHeader))
            {
                return false;
            }

            if (!TokenHandler.CanReadToken(dpopHeader))
            {
                return false;
            }

            var token = TokenHandler.ReadJsonWebToken(dpopHeader);
            var algorithm = token.Alg;
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                return false;
            }

            var allowedAlgs = dpopOptions.Value.AllowedAlgorithms;
            if (!allowedAlgs.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
            {
                var logger = context.RequestServices.GetService<ILogger<DpopValidationMiddleware>>();
                logger?.LogWarning("DPoP Security Block: Rejecting unsupported algorithm: {Alg}", algorithm);
                return false;
            }

            if (!string.Equals(token.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!token.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
            {
                return false;
            }

            var jwkJson = jwkElement.GetRawText();
            if (string.IsNullOrWhiteSpace(jwkJson))
            {
                return false;
            }

            using var jwkDoc = JsonDocument.Parse(jwkJson);
            var root = jwkDoc.RootElement;

            if (root.TryGetProperty("kty", out var ktyProp))
            {
                var kty = ktyProp.GetString();
                if (string.Equals(kty, "oct", StringComparison.OrdinalIgnoreCase))
                {
                    var logger = context.RequestServices.GetService<ILogger<DpopValidationMiddleware>>();
                    logger?.LogCritical("DPoP Attack Blocked: Symmetric oct-key confusion attempt detected.");
                    return false;
                }
            }

            if (root.TryGetProperty("d", out _))
            {
                var logger = context.RequestServices.GetService<ILogger<DpopValidationMiddleware>>();
                logger?.LogCritical("DPoP Attack Blocked: Public JWK header contains private key material.");
                return false;
            }

            SecurityKey signingKey;
            if (root.TryGetProperty("kty", out var ktyVal) &&
                string.Equals(ktyVal.GetString(), "ML-DSA", StringComparison.Ordinal))
            {
                if (!root.TryGetProperty("x", out var xProp) || string.IsNullOrWhiteSpace(xProp.GetString()))
                {
                    return false;
                }

                var publicKeyBytes = Base64UrlEncoder.DecodeBytes(xProp.GetString());
                signingKey = new MlDsaSecurityKey(publicKeyBytes, algorithm);
            }
            else
            {
                signingKey = JsonWebKey.Create(jwkJson);
            }

            var activeFactory = pqcFactory ?? context.RequestServices.GetService<PqcCryptoProviderFactory>();
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
                // nosemgrep: csharp.lang.security.ad.jwt-tokenvalidationparameters-no-expiry-validation.jwt-tokenvalidationparameters-no-expiry-validation
                ValidateLifetime =
                    false, // DPoP proofs do not contain 'exp' claims; lifetime is custom-validated against 'iat' per RFC 9449 in DpopProofValidator
                // nosemgrep: csharp.lang.security.ad.jwt-tokenvalidationparameters-no-expiry-validation.jwt-tokenvalidationparameters-no-expiry-validation
                RequireExpirationTime = false
            };

            var result = await TokenHandler.ValidateTokenAsync(dpopHeader, validationParameters);
            return result.IsValid;
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException or JsonException
                                       or CryptographicException)
        {
            return false;
        }
    }

    private async Task EnforceConstantTimeFailureAsync(long startTimestamp, HttpContext context, string reason)
    {
        AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", reason));

        if (string.Equals(reason, "use_dpop_nonce", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", algs=\"PS256 ES256\"");
        }
        else if (string.Equals(reason, "missing_dpop_proof", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");
        }
        else
        {
            context.Response.Headers.Append("WWW-Authenticate",
                "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/problem+json; charset=utf-8";

        var jitterMs = RandomNumberGenerator.GetInt32(0, 16);
        var targetDuration = TimeSpan.FromMilliseconds(TargetFailureFloorMs + jitterMs);

        var elapsed = timeProvider.GetElapsedTime(startTimestamp);
        var remaining = targetDuration - elapsed;

        if (remaining > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(remaining, timeProvider, context.RequestAborted).ConfigureAwait(false);
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

    private static string? TryExtractProofThumbprint(string dpopHeader, IDpopThumbprintComputer thumbprintComputer)
    {
        try
        {
            if (!TokenHandler.CanReadToken(dpopHeader))
            {
                return null;
            }

            var token = TokenHandler.ReadJsonWebToken(dpopHeader);
            if (!token.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
            {
                return null;
            }

            var jwkJson = jwkElement.GetRawText();
            if (string.IsNullOrWhiteSpace(jwkJson))
            {
                return null;
            }

            using var jwkDoc = JsonDocument.Parse(jwkJson);
            return thumbprintComputer.Compute(jwkDoc.RootElement);
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException or JsonException)
        {
            return null;
        }
    }

    private static string GenerateNonce()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes.ToArray());
    }

    private sealed record NonceRotationState(
        HttpContext HttpContext,
        IDpopNonceStore NonceStore,
        string Thumbprint,
        string NewNonce);
}
