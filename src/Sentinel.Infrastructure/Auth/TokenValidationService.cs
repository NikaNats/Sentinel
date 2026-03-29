using System.Security.Claims;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.Session;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Infrastructure.Auth;

internal sealed class TokenValidationService(
    IJtiReplayCache replayCache,
    ISessionBlacklistCache sessionBlacklist,
    ISecurityEventEmitter eventEmitter,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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
            var remainingTtl = expTime - _timeProvider.GetUtcNow();
            if (remainingTtl <= TimeSpan.Zero)
            {
                return TokenValidationOutcome.Fail("Token is already expired.");
            }

            if (!IsRefreshFlow(context, principal))
            {
                var stored = await replayCache.TryMarkUsedAsync(jti, expTime, ct);
                if (!stored)
                {
                    eventEmitter.EmitTokenReplay(jti, principal.FindFirst("sub")?.Value, "sentinel-api-client",
                        SecurityContextHasher.HashIp(context));
                    return TokenValidationOutcome.Fail("Token replay detected.");
                }
            }

            var sid = principal.FindFirst("sid")?.Value;
            if (string.IsNullOrWhiteSpace(sid))
            {
                return TokenValidationOutcome.Success;
            }

            var isBlacklisted = await sessionBlacklist.IsBlacklistedAsync(sid, ct);
            if (!isBlacklisted)
            {
                return TokenValidationOutcome.Success;
            }

            return TokenValidationOutcome.Fail("Session has been terminated.");
        }
        catch (ReplayCacheUnavailableException ex)
        {
            return TokenValidationOutcome.Fail(ex);
        }
        catch (SessionBlacklistUnavailableException ex)
        {
            return TokenValidationOutcome.Fail(ex);
        }
    }

    private static bool IsRefreshFlow(HttpContext context, ClaimsPrincipal principal)
    {
        if (context.Request.Path.Value?.Contains("/auth/refresh", StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }

        var grantType = principal.FindFirst("grant_type")?.Value;
        if (string.Equals(grantType, "refresh_token", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var tokenUse = principal.FindFirst("token_use")?.Value;
        if (string.Equals(tokenUse, "refresh", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(tokenUse, "refresh_token", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var tokenType = principal.FindFirst("typ")?.Value ?? principal.FindFirst("token_type")?.Value;
        return string.Equals(tokenType, "refresh", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(tokenType, "refresh_token", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record TokenValidationOutcome(bool IsSuccess, string? FailureReason, Exception? FailureException)
{
    public static TokenValidationOutcome Success { get; } = new(true, null, null);

    public static TokenValidationOutcome Fail(string failureReason) => new(false, failureReason, null);

    public static TokenValidationOutcome Fail(Exception failureException) => new(false, null, failureException);
}
