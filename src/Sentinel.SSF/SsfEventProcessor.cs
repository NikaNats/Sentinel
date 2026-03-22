using System.Text.Json;

namespace Sentinel.SSF;

/// <summary>
/// Processes Server-Sent Event (SSF) tokens for real-time security event notification (RFC 8936 / CAEP).
/// Handles session revocation, subject-wide invalidation, and status/credential changes.
/// </summary>
public sealed class SsfEventProcessor : ISsfEventProcessor
{
    private readonly ISsfTokenValidator _tokenValidator;
    private readonly ISessionBlacklistCache _blacklistCache;
    private readonly IAuthRevocationService _authRevocationService;
    private readonly SsfProcessingOptions _options;

    // IANA-registered event type URIs (RFC 8936)
    private const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private const string UserStatusChangedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/user-status-changed";

    private const string CredentialChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    /// <summary>
    /// Initializes a new instance of the SsfEventProcessor.
    /// </summary>
    /// <param name="tokenValidator">Validates SET token signatures and structure.</param>
    /// <param name="blacklistCache">Caches blacklisted session IDs.</param>
    /// <param name="authRevocationService">Revokes auth for entire subjects.</param>
    /// <param name="options">Configuration for event processing.</param>
    public SsfEventProcessor(
        ISsfTokenValidator tokenValidator,
        ISessionBlacklistCache blacklistCache,
        IAuthRevocationService authRevocationService,
        SsfProcessingOptions? options = null)
    {
        _tokenValidator = tokenValidator ?? throw new ArgumentNullException(nameof(tokenValidator));
        _blacklistCache = blacklistCache ?? throw new ArgumentNullException(nameof(blacklistCache));
        _authRevocationService = authRevocationService ?? throw new ArgumentNullException(nameof(authRevocationService));
        _options = options ?? new SsfProcessingOptions();
    }

    /// <summary>
    /// Processes a Server-Sent Event token.
    /// </summary>
    /// <remarks>
    /// Processing flow:
    /// 1. Validates SET token signature and issuer claims
    /// 2. Processes each event in the token:
    ///    - session-revoked: Blacklists specific session or revokes all sessions for subject
    ///    - user-status-changed: Revokes all sessions for affected subject
    ///    - credential-change: Revokes all sessions for affected subject
    /// 3. Returns success if all events processed; partial failures continue processing remaining events
    /// </remarks>
    /// <param name="setToken">The SET JWT token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>SecurityResult indicating processing success or failure reason.</returns>
    public async Task<SecurityResult> ProcessAsync(
        string setToken,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(setToken))
        {
            return SecurityResult.Failure("SET token is required.");
        }

        try
        {
            var validation = await _tokenValidator.ValidateAsync(setToken, cancellationToken);
            if (!validation.IsValid || validation.Token is null)
            {
                return SecurityResult.Failure(validation.Error ?? "SET token validation failed.");
            }

            var ttlSeconds = _options.SessionRevocationTtlSeconds <= 0
                ? 28_800
                : _options.SessionRevocationTtlSeconds;
            var ttl = TimeSpan.FromSeconds(ttlSeconds);

            foreach (var (eventType, payload) in validation.Token.Events)
            {
                await ProcessEventAsync(eventType, payload, validation.Token, ttl, cancellationToken);
            }

            return SecurityResult.CreateSuccess();
        }
        catch (OperationCanceledException)
        {
            return SecurityResult.Failure("SSF processing was cancelled.");
        }
#pragma warning disable CA1031  // Recover from all exceptions during processing
        catch (Exception)
        {
            return SecurityResult.Failure("SSF processing failed.");
        }
#pragma warning restore CA1031
    }

    private async Task ProcessEventAsync(
        string eventType,
        JsonElement payload,
        Sentinel.Security.Abstractions.SSF.SsfEventToken token,
        TimeSpan ttl,
        CancellationToken cancellationToken)
    {
        switch (eventType)
        {
            case SessionRevokedEventType:
                await ProcessSessionRevokedAsync(payload, token, ttl, cancellationToken);
                break;

            case UserStatusChangedEventType:
                await ProcessUserStatusChangedAsync(payload, token, cancellationToken);
                break;

            case CredentialChangeEventType:
                await ProcessCredentialChangeAsync(payload, token, cancellationToken);
                break;
        }
    }

    private async Task ProcessSessionRevokedAsync(
        JsonElement payload,
        Sentinel.Security.Abstractions.SSF.SsfEventToken token,
        TimeSpan ttl,
        CancellationToken cancellationToken)
    {
        try
        {
            var data = JsonSerializer.Deserialize<SessionRevokedPayload>(payload.GetRawText());
            if (data is null)
            {
                return;
            }

            // If specific session ID provided, blacklist that session
            if (!string.IsNullOrWhiteSpace(data.SessionId))
            {
                var expiresAt = DateTimeOffset.UtcNow.Add(ttl);
                await _blacklistCache.BlacklistSessionAsync(data.SessionId, expiresAt, cancellationToken);
                return;
            }

            // If no session ID, revoke all sessions for subject
            var subject = data.Subject ?? token.Subject;
            if (!string.IsNullOrWhiteSpace(subject))
            {
                await _authRevocationService.RevokeAllSessionsAsync(subject, cancellationToken);
            }
        }
#pragma warning disable CA1031  // Continue processing other events if one fails
        catch
        {
            // Silent failure on event processing - continue with next event
        }
#pragma warning restore CA1031
    }

    private async Task ProcessUserStatusChangedAsync(
        JsonElement payload,
        Sentinel.Security.Abstractions.SSF.SsfEventToken token,
        CancellationToken cancellationToken)
    {
        try
        {
            var data = JsonSerializer.Deserialize<UserStatusChangedPayload>(payload.GetRawText());
            var subject = data?.Subject ?? token.Subject;

            if (!string.IsNullOrWhiteSpace(subject))
            {
                await _authRevocationService.RevokeAllSessionsAsync(subject, cancellationToken);
            }
        }
#pragma warning disable CA1031  // Continue processing other events if one fails
        catch
        {
            // Silent failure on event processing - continue with next event
        }
#pragma warning restore CA1031
    }

    private async Task ProcessCredentialChangeAsync(
        JsonElement payload,
        Sentinel.Security.Abstractions.SSF.SsfEventToken token,
        CancellationToken cancellationToken)
    {
        try
        {
            var data = JsonSerializer.Deserialize<CredentialChangePayload>(payload.GetRawText());
            var subject = data?.Subject ?? token.Subject;

            if (!string.IsNullOrWhiteSpace(subject))
            {
                await _authRevocationService.RevokeAllSessionsAsync(subject, cancellationToken);
            }
        }
#pragma warning disable CA1031  // Continue processing other events if one fails
        catch
        {
            // Silent failure on event processing - continue with next event
        }
#pragma warning restore CA1031
    }
}

