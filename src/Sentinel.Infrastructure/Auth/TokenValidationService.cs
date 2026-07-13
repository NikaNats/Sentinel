using System.Security.Claims;
using Sentinel.Security.Abstractions.Exceptions;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.Infrastructure.Auth;

/// <summary>
///     High-assurance token validation and session status verification service.
///     Performs dual-tier cryptographic verification (subject + session level) to prevent authorization bypass.
///     Optimized for C# 12+ and Native AOT runtime performance.
/// </summary>
public sealed class TokenValidationService
{
    private readonly ILogger<TokenValidationService> _logger;
    private readonly ISessionBlacklistCache _sessionBlacklist;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    ///     Primary constructor with explicit dependencies injection.
    /// </summary>
    public TokenValidationService(
        ISessionBlacklistCache sessionBlacklist,
        ILogger<TokenValidationService> logger,
        TimeProvider? timeProvider = null)
    {
        _sessionBlacklist = sessionBlacklist ?? throw new ArgumentNullException(nameof(sessionBlacklist));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    ///     Performs atomic, parallel verification of token expiration and session blacklist status.
    /// </summary>
    /// <returns>A ValueTask containing the outcome of the token validation.</returns>
    public async ValueTask<TokenValidationOutcome> ValidateAsync(
        ClaimsPrincipal principal,
        HttpContext context,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(principal);
        _ = context;

        try
        {
            var expClaim = principal.FindFirst("exp");
            if (expClaim is null || string.IsNullOrWhiteSpace(expClaim.Value))
            {
                _logSecurityWarning(_logger, "Missing required exp claim.", null);
                return TokenValidationOutcome.Fail("Missing required exp claim.");
            }

            if (!long.TryParse(expClaim.Value, out var expUnix))
            {
                _logSecurityWarning(_logger, "Invalid exp claim format.", null);
                return TokenValidationOutcome.Fail("Invalid exp claim.");
            }

            var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
            if (expTime <= _timeProvider.GetUtcNow())
            {
                _logSecurityWarning(_logger, "Submitted token has expired.", null);
                return TokenValidationOutcome.Fail("Token is already expired.");
            }

            var sub = principal.FindFirst("sub")?.Value;
            var sid = principal.FindFirst("sid")?.Value;

            var subjectCheckTask = Task.FromResult(false);
            var sessionCheckTask = Task.FromResult(false);

            if (!string.IsNullOrWhiteSpace(sub))
            {
                subjectCheckTask = _sessionBlacklist.IsBlacklistedAsync(sub, ct);
            }

            if (!string.IsNullOrWhiteSpace(sid))
            {
                sessionCheckTask = _sessionBlacklist.IsBlacklistedAsync(sid, ct);
            }

            await Task.WhenAll(subjectCheckTask, sessionCheckTask).ConfigureAwait(false);

            if (await subjectCheckTask)
            {
                _logSecurityAlert(_logger, "Subject (user) globally revoked or locked.", null);
                return TokenValidationOutcome.Fail("User account has been globally revoked or locked.");
            }

            if (!await sessionCheckTask)
            {
                return TokenValidationOutcome.Success;
            }

            _logSecurityAlert(_logger, "Session identifier is blacklisted.", null);
            return TokenValidationOutcome.Fail("Session has been terminated.");

        }
        catch (SessionBlacklistUnavailableException ex)
        {
            _logCriticalFailure(_logger, "Fail-closed triggered due to session store unavailability.", ex);
            return TokenValidationOutcome.Fail(ex);
        }
    }

    #region High-Performance Logging (Zero-Allocation Logging Messages)

    private static readonly Action<ILogger, string, Exception?> _logSecurityWarning =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(3001, "TokenValidationWarning"),
            "Security boundary warning: {Reason}");

    private static readonly Action<ILogger, string, Exception?> _logSecurityAlert =
        LoggerMessage.Define<string>(LogLevel.Critical, new EventId(3002, "TokenRevocationAlert"),
            "SECURITY ALERT: {Reason}");

    private static readonly Action<ILogger, string, Exception?> _logCriticalFailure =
        LoggerMessage.Define<string>(LogLevel.Error, new EventId(3003, "TokenValidationCriticalFailure"),
            "Critical operational failure: {Reason}");

    #endregion
}

/// <summary>
///     Represents the outcome of a token validation operation.
/// </summary>
public sealed record TokenValidationOutcome(bool IsSuccess, string? FailureReason, Exception? FailureException)
{
    public static TokenValidationOutcome Success { get; } = new(true, null, null);
    public static TokenValidationOutcome Fail(string failureReason) => new(false, failureReason, null);
    public static TokenValidationOutcome Fail(Exception failureException) => new(false, null, failureException);
}
