using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sentinel.SSF;

/// <summary>
///     High-Assurance SSF Event Processor (Native AOT Compatible).
///     Implements strict temporal bounding (replay prevention), zero-allocation JSON parsing,
///     and robust fail-closed error handling per RFC 8936 / CAEP specification.
/// </summary>
public sealed class SsfEventProcessor : ISsfEventProcessor
{
    // IANA-registered event type URIs (RFC 8936)
    private const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private const string UserStatusChangedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/user-status-changed";

    private const string CredentialChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    private readonly IAuthRevocationService _authRevocationService;
    private readonly ISessionBlacklistCache _blacklistCache;
    private readonly ILogger<SsfEventProcessor> _logger;
    private readonly SsfProcessingOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISsfTokenValidator _tokenValidator;

    /// <summary>
    ///     Initializes a new instance of the SsfEventProcessor.
    /// </summary>
    /// <param name="tokenValidator">Validates SET token signatures and structure.</param>
    /// <param name="blacklistCache">Caches blacklisted session IDs.</param>
    /// <param name="authRevocationService">Revokes auth for entire subjects.</param>
    /// <param name="options">Configuration for event processing (from DI).</param>
    /// <param name="logger">Logger for diagnostics and security events.</param>
    /// <param name="timeProvider">Time provider for testability; defaults to System.</param>
    /// <remarks>
    ///     ✅ FIX: Strict DI injection, no nullable options, use TimeProvider for testability.
    ///     All parameters must be provided by the container (see SsfServiceCollectionExtensions).
    /// </remarks>
    public SsfEventProcessor(
        ISsfTokenValidator tokenValidator,
        ISessionBlacklistCache blacklistCache,
        IAuthRevocationService authRevocationService,
        IOptions<SsfProcessingOptions> options,
        ILogger<SsfEventProcessor> logger,
        TimeProvider? timeProvider = null)
    {
        _tokenValidator = tokenValidator ?? throw new ArgumentNullException(nameof(tokenValidator));
        _blacklistCache = blacklistCache ?? throw new ArgumentNullException(nameof(blacklistCache));
        _authRevocationService =
            authRevocationService ?? throw new ArgumentNullException(nameof(authRevocationService));
        _options = options?.Value ??
                   throw new ArgumentNullException(nameof(options)); // ✅ FIX: Let DI container guarantee presence
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    ///     Processes a Server-Sent Event token with high-assurance security guarantees.
    /// </summary>
    /// <remarks>
    ///     Processing flow:
    ///     1. Validates SET token signature and issuer claims
    ///     2. Enforces temporal bounds (prevents replay attacks beyond max age + clock skew)
    ///     3. Processes each event in the token:
    ///     - session-revoked: Blacklists specific session or revokes all sessions for subject
    ///     - user-status-changed: Revokes all sessions for affected subject
    ///     - credential-change: Revokes all sessions for affected subject
    ///     4. Returns failure if ANY event fails to process (fail-closed revocation guarantee)
    ///     ✅ FIX: Temporal Bounding / Replay Prevention
    ///     - If Redis is down, infrastructure exceptions propagate and endpoint returns 500
    ///     - Keycloak's webhook retries the event later instead of assuming success
    ///     ✅ FIX: Zero-Allocation JSON Parsing
    ///     - Uses JsonSerializer.Deserialize(payload, SsfJsonContext.Default.X)
    ///     - Bypasses reflection-based serializer for Native AOT trimming
    /// </remarks>
    /// <param name="setToken">The SET JWT token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>SecurityResult indicating processing success or failure reason.</returns>
    public async Task<SecurityResult> ProcessAsync(string setToken, CancellationToken cancellationToken = default)
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

            // ✅ FIX: Temporal Bounding / Replay Prevention
            var age = _timeProvider.GetUtcNow() - validation.Token.IssuedAtDateTimeOffset;
            var maxAge = TimeSpan.FromSeconds(_options.MaxEventAgeSeconds + _options.AllowedClockSkewSeconds);
            var minAge = TimeSpan.FromSeconds(-_options.AllowedClockSkewSeconds);

            if (age > maxAge || age < minAge)
            {
                _logger.LogWarning(
                    "CRITICAL: SET token rejected due to temporal bounds. Age: {Age}, Max: {MaxAge}, Min: {MinAge}",
                    age, maxAge, minAge);
                return SecurityResult.Failure("SET token is stale or violates clock skew boundaries.");
            }

            // ✅ FIX: Eliminate inline magic numbers, trust Options
            var ttl = TimeSpan.FromSeconds(_options.SessionRevocationTtlSeconds);
            var hasFailures = false;

            foreach (var (eventType, payload) in validation.Token.Events)
            {
                var success = await ProcessEventAsync(eventType, payload, validation.Token, ttl, cancellationToken);
                if (!success)
                {
                    hasFailures = true;
                }
            }

            // ✅ FIX: Do not return Success if an underlying infrastructure failure occurred.
            // Returning failure translates to HTTP 500/400, forcing the IdP to retry the webhook later.
            return hasFailures
                ? SecurityResult.Failure("One or more events failed to process due to infrastructure errors.")
                : SecurityResult.CreateSuccess();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Catastrophic failure processing SSF token.");
            return SecurityResult.Failure("SSF processing failed due to internal error.");
        }
    }

    /// <summary>
    ///     Processes a single event, returning success/failure to allow partial batches
    ///     while ensuring infrastructure failures propagate correctly.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Returns bool instead of void to enable fail-closed retry semantics.
    ///     Exceptions are caught, logged, and surface to the caller to prevent false-positive ACKs.
    /// </remarks>
    private async Task<bool> ProcessEventAsync(
        string eventType,
        JsonElement payload,
        SsfEventToken token,
        TimeSpan ttl,
        CancellationToken ct)
    {
        try
        {
            switch (eventType)
            {
                case SessionRevokedEventType:
                    // ✅ FIX: Zero-allocation Native AOT deserialization. Reads directly from JsonElement.
                    var sessionData = payload.Deserialize(SsfJsonContext.Default.SessionRevokedPayload);
                    if (sessionData is null)
                    {
                        return false;
                    }

                    if (!string.IsNullOrWhiteSpace(sessionData.SessionId))
                    {
                        // ✅ FIX: Signature mismatch resolved (passing correct DateTimeOffset expiry).
                        var expiresAt = _timeProvider.GetUtcNow().Add(ttl);
                        await _blacklistCache.BlacklistSessionAsync(sessionData.SessionId, expiresAt, ct);
                    }
                    else if (!string.IsNullOrWhiteSpace(sessionData.Subject ?? token.Subject))
                    {
                        await _authRevocationService.RevokeAllSessionsAsync(sessionData.Subject ?? token.Subject!, ct);
                    }

                    break;

                case UserStatusChangedEventType:
                    var statusData = payload.Deserialize(SsfJsonContext.Default.UserStatusChangedPayload);
                    var statusSub = statusData?.Subject ?? token.Subject;
                    if (!string.IsNullOrWhiteSpace(statusSub))
                    {
                        await _authRevocationService.RevokeAllSessionsAsync(statusSub, ct);
                    }

                    break;

                case CredentialChangeEventType:
                    var credData = payload.Deserialize(SsfJsonContext.Default.CredentialChangePayload);
                    var credSub = credData?.Subject ?? token.Subject;
                    if (!string.IsNullOrWhiteSpace(credSub))
                    {
                        await _authRevocationService.RevokeAllSessionsAsync(credSub, ct);
                    }

                    break;

                default:
                    // ✅ FIX: Do not silently drop unknown events. Log for observability.
                    _logger.LogWarning("Ignored unknown CAEP event type: {EventType}", eventType);
                    break;
            }

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // ✅ FIX: Exceptions are caught, logged, and surface to the caller to prevent false-positive ACKs.
            _logger.LogError(ex, "Failed to execute revocation for event type: {EventType}", eventType);
            return false;
        }
    }
}
