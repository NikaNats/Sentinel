namespace Sentinel.Application.Auth.Interfaces;

public interface IEmailVerificationTokenStore
{
    Task<bool> StoreAsync(string token, string keycloakUserId, TimeSpan ttl, CancellationToken ct);
    Task<string?> ConsumeAsync(string token, CancellationToken ct);
}
