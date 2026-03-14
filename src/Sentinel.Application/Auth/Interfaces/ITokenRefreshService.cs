namespace Sentinel.Application.Auth.Interfaces;

public record TokenRefreshResult(bool IsSuccess, string? AccessToken, string? RefreshToken, bool IsReuseDetected);

public interface ITokenRefreshService
{
    Task<TokenRefreshResult> RefreshTokenAsync(string refreshToken, string dpopProof, CancellationToken ct);
}
