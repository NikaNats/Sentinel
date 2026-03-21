namespace Sentinel.Infrastructure.Auth.Ssf;

public interface ISsfTokenValidator
{
    Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken ct);
}
