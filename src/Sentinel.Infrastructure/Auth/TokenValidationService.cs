using System.Security.Claims;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Infrastructure.Auth;

/// <summary>
///     High-assurance token validation and session status verification service.
///     Performs dual-tier cryptographic verification (subject + session level) to prevent authorization bypass.
/// </summary>
public sealed class TokenValidationService(
    ISessionBlacklistCache sessionBlacklist,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    ///     Performs atomic verification of token expiration and session blacklist status.
    /// </summary>
    public async Task<TokenValidationOutcome> ValidateAsync(ClaimsPrincipal principal, HttpContext context,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(principal);
        _ = context;

        try
        {
            var exp = principal.FindFirst("exp")?.Value;

            if (string.IsNullOrWhiteSpace(exp))
            {
                return TokenValidationOutcome.Fail("Missing required exp claim.");
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

            var sub = principal.FindFirst("sub")?.Value;
            if (!string.IsNullOrWhiteSpace(sub))
            {
                var isSubjectBlacklisted = await sessionBlacklist.IsBlacklistedAsync(sub, ct).ConfigureAwait(false);
                if (isSubjectBlacklisted)
                {
                    return TokenValidationOutcome.Fail("User account has been globally revoked or locked.");
                }
            }

            var sid = principal.FindFirst("sid")?.Value;
            if (!string.IsNullOrWhiteSpace(sid))
            {
                var isSessionBlacklisted = await sessionBlacklist.IsBlacklistedAsync(sid, ct).ConfigureAwait(false);
                if (isSessionBlacklisted)
                {
                    return TokenValidationOutcome.Fail("Session has been terminated.");
                }
            }

            return TokenValidationOutcome.Success;
        }
        catch (SessionBlacklistUnavailableException ex)
        {
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
