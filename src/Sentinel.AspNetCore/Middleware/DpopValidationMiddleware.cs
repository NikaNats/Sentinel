// Sentinel Security API - FAPI 2.0 Compliant

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Diagnostics;
using IDpopProofValidator = Sentinel.Security.Abstractions.DPoP.IDpopProofValidator;

namespace Sentinel.AspNetCore.Middleware;

public sealed class DpopValidationMiddleware(
    RequestDelegate next,
    IDpopProofValidator validator,
    IDpopNonceStore nonceStore,
    IDpopThumbprintComputer thumbprintComputer)
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var ipHash = SecurityContextHasher.HashIp(context);
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader) ||
            !authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(authHeader) &&
                authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var bearerToken = authHeader["Bearer ".Length..].Trim();
                if (bearerToken.Contains('~', StringComparison.Ordinal))
                {
                    await next(context);
                    return;
                }

                AuthTelemetry.DpopFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "bearer_downgrade_attempt"));
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            await next(context);
            return;
        }

        var dpopProof = context.Request.Headers["DPoP"].ToString();
        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "missing_dpop_proof"));
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = authHeader["DPoP ".Length..].Trim();
        // RFC 9449 section 4.2: htu excludes query string and fragment.
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        var thumbprint = TryExtractProofThumbprint(dpopProof, thumbprintComputer);
        string? expectedNonce = null;
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            expectedNonce = await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted);
        }

        // ✅ FIX: Validate the proof and check expected nonce (but DO NOT consume it yet)
        var validationRequest = new DpopValidationRequest(dpopProof, context.Request.Method, new Uri(requestUrl), token,
            expectedNonce);
        var validationResult = await validator.ValidateAsync(validationRequest, context.RequestAborted);

        // Convert domain result to HTTP response format
        var result = validationResult.ToHttpResult();

        if (!result.IsValid)
        {
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "invalid_dpop_proof"));

            if (string.Equals(result.Error, "use_dpop_nonce", StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(thumbprint))
            {
                var challengeNonce = GenerateNonce();
                var stored = await nonceStore.TryStoreNonceAsync(thumbprint, challengeNonce, TimeSpan.FromMinutes(5),
                    context.RequestAborted);
                var effectiveNonce = stored
                    ? challengeNonce
                    : await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted) ?? challengeNonce;

                context.Response.Headers.Append("DPoP-Nonce", effectiveNonce);
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"use_dpop_nonce\", algs=\"PS256 ES256\"");
            }
            else
            {
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Propagate DPoP key info via Activity baggage for downstream security auditing and correlation
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            Activity.Current?.AddBaggage("dpop.jkt", thumbprint);
            context.Items["dpop.jkt"] = thumbprint; // Also store in context for middleware access
        }

        if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(result.NewNonce))
        {
            var storedNonce = await nonceStore.TryStoreNonceAsync(thumbprint, result.NewNonce, TimeSpan.FromMinutes(5),
                context.RequestAborted);
            var nextNonce = storedNonce
                ? result.NewNonce
                : await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted) ?? result.NewNonce;

            context.Response.OnStarting(static state =>
            {
                var (httpContext, nonce) = ((HttpContext HttpContext, string Nonce))state;
                httpContext.Response.Headers["DPoP-Nonce"] = nonce;
                return Task.CompletedTask;
            }, (context, nextNonce));
        }

        // ✅ FIX: Execute downstream pipeline FIRST
        await next(context);

        // ✅ FIX: Consume nonce ONLY if the request succeeded (2xx or 3xx)
        // This ensures that legitimate retries of 5xx errors do not incur an extra 401 round-trip.
        // Concurrent replay protection is strictly handled by the JtiReplayCache in TokenValidationService.
        if (context.Response.StatusCode is >= 200 and < 400 &&
            !string.IsNullOrWhiteSpace(thumbprint) &&
            !string.IsNullOrWhiteSpace(expectedNonce))
        {
            _ = await nonceStore.ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, context.RequestAborted);
        }

    }

    private static string? TryExtractProofThumbprint(string dpopHeader, IDpopThumbprintComputer thumbprintComputer)
    {
        if (!TokenHandler.CanReadToken(dpopHeader))
        {
            return null;
        }

        var token = TokenHandler.ReadJsonWebToken(dpopHeader);
        // ✅ FIX: Strongly type the extraction to JsonElement.
        if (!token.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
        {
            return null;
        }

        // ✅ FIX: Use GetRawText() to retrieve the actual JSON string, never .ToString()
        // On modern .NET runtimes, .ToString() returns "System.Text.Json.JsonElement" instead of the actual JSON payload
        var jwkJson = jwkElement.GetRawText();
        if (string.IsNullOrWhiteSpace(jwkJson))
        {
            return null;
        }

        using var jwkDoc = JsonDocument.Parse(jwkJson);
        var thumbprint = thumbprintComputer.Compute(jwkDoc.RootElement);
        return string.IsNullOrWhiteSpace(thumbprint) ? null : thumbprint;
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }
}
