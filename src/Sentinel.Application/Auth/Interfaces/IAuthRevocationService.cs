using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface IAuthRevocationService
{
    Task<IReadOnlyCollection<UserSessionInfo>> GetActiveSessionsAsync(string subjectId, CancellationToken ct);
    Task<bool> RevokeSessionAsync(string subjectId, string sessionId, CancellationToken ct);
    Task<bool> RevokeCurrentSessionAsync(string refreshToken, CancellationToken ct);
    Task<bool> RevokeAllSessionsAsync(string subjectId, CancellationToken ct);
    Task<bool> DeleteAccountAsync(string subjectId, CancellationToken ct);
}
