using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Middleware;

public sealed class DpopValidationMiddleware(
    RequestDelegate next,
    IDpopProofValidator validator,
    IDpopNonceStore nonceStore,
    ISecurityEventEmitter emitter)
{
    private static readonly Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler TokenHandler = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var ipHash = SecurityContextHasher.HashIp(context);
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                emitter.EmitAuthFailure("bearer_downgrade_attempt", context.User.FindFirst("sub")?.Value, ipHash);
                AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "bearer_downgrade_attempt"));
                context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            await next(context);
            return;
        }

        var dpopProof = context.Request.Headers["DPoP"].ToString();
        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            emitter.EmitAuthFailure("missing_dpop_proof", context.User.FindFirst("sub")?.Value, ipHash);
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "missing_dpop_proof"));
            context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"missing_dpop_proof\"");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = authHeader["DPoP ".Length..].Trim();
        var requestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";

        var thumbprint = TryExtractProofThumbprint(dpopProof);
        string? expectedNonce = null;
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            expectedNonce = await nonceStore.ConsumeNonceAsync(thumbprint, context.RequestAborted);
        }

        DpopValidationResult result;
        try
        {
            result = await validator.ValidateAsync(dpopProof, token, context.Request.Method, requestUrl, expectedNonce, context.RequestAborted);
        }
        catch (ReplayCacheUnavailableException)
        {
            emitter.EmitAuthFailure("dpop_replay_cache_unavailable", context.User.FindFirst("sub")?.Value, ipHash);
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Type = "/errors/replay-cache-unavailable",
                Title = "Security subsystem unavailable",
                Detail = "DPoP replay protection is temporarily unavailable.",
                Status = StatusCodes.Status503ServiceUnavailable
            });
            return;
        }

        if (!result.IsValid)
        {
            emitter.EmitAuthFailure("invalid_dpop_proof", context.User.FindFirst("sub")?.Value, ipHash);
            AuthTelemetry.DpopFailures.Add(1, new KeyValuePair<string, object?>("reason", "invalid_dpop_proof"));

            if (string.Equals(result.Error, "use_dpop_nonce", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(thumbprint))
            {
                var challengeNonce = GenerateNonce();
                await nonceStore.StoreNonceAsync(thumbprint, challengeNonce, TimeSpan.FromMinutes(5), context.RequestAborted);
                context.Response.Headers.Append("DPoP-Nonce", challengeNonce);
                context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", algs=\"PS256 ES256\"");
            }
            else
            {
                context.Response.Headers.Append("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"PS256 ES256\"");
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (!string.IsNullOrWhiteSpace(thumbprint) && !string.IsNullOrWhiteSpace(result.NewNonce))
        {
            await nonceStore.StoreNonceAsync(thumbprint, result.NewNonce, TimeSpan.FromMinutes(5), context.RequestAborted);
            context.Response.Headers.Append("DPoP-Nonce", result.NewNonce);
        }

        await next(context);
    }

    private static string? TryExtractProofThumbprint(string dpopHeader)
    {
        if (!TokenHandler.CanReadToken(dpopHeader))
        {
            return null;
        }

        var token = TokenHandler.ReadJsonWebToken(dpopHeader);
        if (!token.TryGetHeaderValue<object>("jwk", out var jwkObj) || jwkObj is null)
        {
            return null;
        }

        var jwkJson = jwkObj.ToString();
        if (string.IsNullOrWhiteSpace(jwkJson))
        {
            return null;
        }

        using var jwkDoc = JsonDocument.Parse(jwkJson);
        var jwk = jwkDoc.RootElement;

        if (jwk.TryGetProperty("kty", out var ktyElement)
            && string.Equals(ktyElement.GetString(), "EC", StringComparison.Ordinal)
            && jwk.TryGetProperty("crv", out var crv)
            && jwk.TryGetProperty("x", out var x)
            && jwk.TryGetProperty("y", out var y))
        {
            var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["crv"] = crv.GetString() ?? string.Empty,
                ["kty"] = "EC",
                ["x"] = x.GetString() ?? string.Empty,
                ["y"] = y.GetString() ?? string.Empty
            });

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(hash);
        }

        if (jwk.TryGetProperty("kty", out var rsaKty)
            && string.Equals(rsaKty.GetString(), "RSA", StringComparison.Ordinal)
            && jwk.TryGetProperty("e", out var e)
            && jwk.TryGetProperty("n", out var n))
        {
            var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["e"] = e.GetString() ?? string.Empty,
                ["kty"] = "RSA",
                ["n"] = n.GetString() ?? string.Empty
            });

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(hash);
        }

        return null;
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(bytes);
    }
}
