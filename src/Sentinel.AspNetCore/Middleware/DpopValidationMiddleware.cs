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

internal sealed class DpopValidationMiddleware
{
    private const long TargetFailureFloorMs = 1;
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);

    private readonly RequestDelegate _next;
    private readonly IDpopThumbprintComputer _thumbprintComputer;

    public DpopValidationMiddleware(
        RequestDelegate next,
        IDpopThumbprintComputer thumbprintComputer)
    {
        _next = next;
        _thumbprintComputer = thumbprintComputer;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IDpopProofValidator validator,
        IDpopNonceStore nonceStore)
    {
        var sw = Stopwatch.StartNew();

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
                    await _next(context);
                    return;
                }

                AuthTelemetry.DpopFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "bearer_downgrade_attempt"));
                context.Response.Headers.Append("WWW-Authenticate",
                    "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");

                await EnforceConstantTimeFailureAsync(sw, context);
                return;
            }

            await _next(context);
            return;
        }

        var dpopProof = context.Request.Headers["DPoP"].ToString();
        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "missing_dpop_proof"));
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");

            await EnforceConstantTimeFailureAsync(sw, context);
            return;
        }

        var token = authHeader["DPoP ".Length..].Trim();
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        var thumbprint = TryExtractProofThumbprint(dpopProof, _thumbprintComputer);
        string? expectedNonce = null;
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            expectedNonce = await nonceStore.GetNonceAsync(thumbprint, context.RequestAborted);
        }

        var validationRequest = new DpopValidationRequest(dpopProof, context.Request.Method, new Uri(requestUrl), token,
            expectedNonce);
        var validationResult = await validator.ValidateAsync(validationRequest, context.RequestAborted);
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

            await EnforceConstantTimeFailureAsync(sw, context);
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

                callbackState.HttpContext.Response.Headers["DPoP-Nonce"] = nonceToEmit;
            }, new NonceRotationState(context, nonceStore, thumbprint, expectedNonce, result.NewNonce));
        }

        await _next(context);
    }

    private static async Task EnforceConstantTimeFailureAsync(Stopwatch sw, HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        sw.Stop();
        var elapsedMs = sw.ElapsedMilliseconds;
        var paddingNeeded = TargetFailureFloorMs - elapsedMs;

        var jitter = RandomNumberGenerator.GetInt32(0, 15);
        var totalDelay = Math.Max(0, paddingNeeded) + jitter;

        if (totalDelay > 0)
        {
            await Task.Delay((int)totalDelay, context.RequestAborted);
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
        catch (Exception ex) when (ex is ArgumentException || ex is SecurityTokenException || ex is JsonException)
        {
            return null;
        }
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    private sealed record NonceRotationState(
        HttpContext HttpContext,
        IDpopNonceStore NonceStore,
        string Thumbprint,
        string? ExpectedNonce,
        string NewNonce);
}
