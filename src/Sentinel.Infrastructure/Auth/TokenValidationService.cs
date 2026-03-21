using System.Security.Claims;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Infrastructure.Auth;

public sealed class TokenValidationService(
    IJtiReplayCache replayCache,
    ISessionBlacklistCache sessionBlacklist,
    ISecurityEventEmitter eventEmitter)
{
    public async Task<TokenValidationOutcome> ValidateAsync(ClaimsPrincipal principal, HttpContext context,
        CancellationToken ct)
    {
        try
        {
            var jti = principal.FindFirst("jti")?.Value;
            var exp = principal.FindFirst("exp")?.Value;

            if (string.IsNullOrWhiteSpace(jti) || string.IsNullOrWhiteSpace(exp))
            {
                return TokenValidationOutcome.Fail("Missing required token claims (jti or exp).");
            }

            if (!long.TryParse(exp, out var expUnix))
            {
                return TokenValidationOutcome.Fail("Invalid exp claim.");
            }

            var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
            var remainingTtl = expTime - DateTimeOffset.UtcNow;
            if (remainingTtl <= TimeSpan.Zero)
            {
                return TokenValidationOutcome.Fail("Token is already expired.");
            }

            var stored = await replayCache.TryStoreIfNotExistsAsync(jti, remainingTtl, ct);
            if (!stored)
            {
                eventEmitter.EmitTokenReplay(jti, principal.FindFirst("sub")?.Value, "sentinel-api-client",
                    SecurityContextHasher.HashIp(context));
                return TokenValidationOutcome.Fail("Token replay detected.");
            }

            var sid = principal.FindFirst("sid")?.Value;
            if (string.IsNullOrWhiteSpace(sid))
            {
                return TokenValidationOutcome.Success;
            }

            var isBlacklisted = await sessionBlacklist.IsSessionBlacklistedAsync(sid, ct);
            if (!isBlacklisted)
            {
                return TokenValidationOutcome.Success;
            }

            eventEmitter.EmitAuthFailure("revoked_session_usage_attempt", principal.FindFirst("sub")?.Value,
                SecurityContextHasher.HashIp(context));
            return TokenValidationOutcome.Fail("Session has been terminated.");
        }
        catch (ReplayCacheUnavailableException ex)
        {
            eventEmitter.EmitAuthFailure("replay_cache_unavailable", principal.FindFirst("sub")?.Value,
                SecurityContextHasher.HashIp(context));
            return TokenValidationOutcome.Fail(ex);
        }
    }
}

public sealed record TokenValidationOutcome(bool IsSuccess, string? FailureReason, Exception? FailureException)
{
    public static TokenValidationOutcome Success { get; } = new(true, null, null);

    public static TokenValidationOutcome Fail(string failureReason) => new(false, failureReason, null);

    public static TokenValidationOutcome Fail(Exception failureException) => new(false, null, failureException);
}
