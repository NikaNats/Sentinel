using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Stores;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Diagnostics;
using IDpopProofValidator = Sentinel.Security.Abstractions.DPoP.IDpopProofValidator;

namespace Sentinel.AspNetCore.Middleware;

internal sealed class DpopValidationMiddleware(
    RequestDelegate next,
    IDpopThumbprintComputer thumbprintComputer,
    TimeProvider timeProvider,
    L1AntiFloodCache l1AntiFloodCache)
{
    private const long TargetFailureFloorMs = 100;
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);

    public async Task InvokeAsync(
        HttpContext context,
        IDpopProofValidator validator,
        IDpopNonceStore nonceStore)
    {
        var startTimestamp = timeProvider.GetTimestamp();

        var ipHash = SecurityContextHasher.HashIp(context);
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

                AuthTelemetry.DpopFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "bearer_downgrade_attempt"));
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");

                await EnforceConstantTimeFailureAsync(startTimestamp, context);
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
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "missing_dpop_proof"));
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");

            await EnforceConstantTimeFailureAsync(startTimestamp, context);
            return;
        }

        var token = authHeaderSpan["DPoP ".Length..].Trim().ToString();
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        var thumbprint = TryExtractProofThumbprint(dpopProofString, thumbprintComputer);
        string? expectedNonce = null;

        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            if (l1AntiFloodCache.IsTemporarilyBlacklisted(thumbprint))
            {
                AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "l1_anti_flood_blocked"));
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
                await EnforceConstantTimeFailureAsync(startTimestamp, context);
                return;
            }

            expectedNonce = await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted);
        }

        var validationRequest = new DpopValidationRequest(dpopProofString, context.Request.Method, new Uri(requestUrl),
            token, expectedNonce);
        var validationResult = await validator.ValidateAsync(validationRequest, context.RequestAborted);
        var result = validationResult.ToHttpResult();

        if (!result.IsValid)
        {
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "invalid_dpop_proof"));

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
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"use_dpop_nonce\", algs=\"PS256 ES256\"");
            }
            else
            {
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
            }

            await EnforceConstantTimeFailureAsync(startTimestamp, context);
            return;
        }

        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            Activity.Current?.AddBaggage("dpop.jkt", thumbprint);
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

                if (!string.IsNullOrWhiteSpace(callbackState.ExpectedNonce))
                {
                    _ = await callbackState.NonceStore.ConsumeNonceIfMatchesAsync(
                        callbackState.Thumbprint,
                        callbackState.ExpectedNonce,
                        callbackState.HttpContext.RequestAborted);
                }

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
            }, new NonceRotationState(context, nonceStore, thumbprint, expectedNonce, result.NewNonce));
        }

        await next(context);
    }

    private async Task EnforceConstantTimeFailureAsync(long startTimestamp, HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

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
            }
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
            var thumbprint = thumbprintComputer.Compute(jwkDoc.RootElement);
            return string.IsNullOrWhiteSpace(thumbprint) ? null : thumbprint;
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
        string? ExpectedNonce,
        string NewNonce);
}
