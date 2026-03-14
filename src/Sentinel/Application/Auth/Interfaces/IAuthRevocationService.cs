namespace Sentinel.Application.Auth.Interfaces;

public interface IAuthRevocationService
{
    Task<bool> RevokeCurrentSessionAsync(string refreshToken, CancellationToken ct);
    Task<bool> RevokeAllSessionsAsync(string subjectId, CancellationToken ct);
}
