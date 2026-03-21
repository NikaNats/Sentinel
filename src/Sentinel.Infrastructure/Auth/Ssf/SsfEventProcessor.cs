using System.Text.Json;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Auth.Ssf;

public sealed class SsfEventProcessor(
    ISsfTokenValidator tokenValidator,
    ISessionBlacklistCache blacklistCache,
    IAuthRevocationService authRevocationService,
    IOptions<SsfOptions> ssfOptions,
    ILogger<SsfEventProcessor> logger) : ISsfEventProcessor
{
    private const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private const string UserStatusChangedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/user-status-changed";

    private const string CredentialChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
    {
        var validation = await tokenValidator.ValidateAsync(setToken, ct);
        if (!validation.IsValid || validation.Token is null)
        {
            return SsfProcessResult.Unauthorized(validation.Error ?? "Invalid SET.");
        }

        var ttlSeconds = ssfOptions.Value.SessionRevocationTtlSeconds <= 0
            ? 28_800
            : ssfOptions.Value.SessionRevocationTtlSeconds;
        var ttl = TimeSpan.FromSeconds(ttlSeconds);

        foreach (var (eventType, payload) in validation.Token.Events)
        {
            switch (eventType)
            {
                case SessionRevokedEventType:
                {
                    var data = payload.Deserialize<SessionRevokedPayload>();
                    if (data is null)
                    {
                        logger.LogWarning("SSF session-revoked event payload could not be parsed. jti={Jti}",
                            validation.Token.Jti);
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(data.SessionId))
                    {
                        await blacklistCache.BlacklistSessionAsync(data.SessionId, ttl, ct);
                        logger.LogCritical("CAE: Session {Sid} revoked for user {Sub}", data.SessionId, data.Subject);
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(data.Subject))
                    {
                        _ = await authRevocationService.RevokeAllSessionsAsync(data.Subject, ct);
                        logger.LogCritical("CAE: Subject-wide revocation triggered for user {Sub}", data.Subject);
                    }

                    break;
                }
                case UserStatusChangedEventType:
                case CredentialChangeEventType:
                {
                    var data = payload.Deserialize<UserStatusChangedPayload>();
                    var subject = data?.Subject ?? validation.Token.Subject;
                    if (string.IsNullOrWhiteSpace(subject))
                    {
                        logger.LogWarning("SSF subject-level event missing subject. type={EventType} jti={Jti}",
                            eventType, validation.Token.Jti);
                        continue;
                    }

                    _ = await authRevocationService.RevokeAllSessionsAsync(subject, ct);
                    logger.LogCritical("CAE: Subject {Sub} revoked due to event {EventType}", subject, eventType);
                    break;
                }
                default:
                    logger.LogInformation("SSF event type not handled. type={EventType} jti={Jti}", eventType,
                        validation.Token.Jti);
                    break;
            }
        }

        return SsfProcessResult.Success();
    }
}
