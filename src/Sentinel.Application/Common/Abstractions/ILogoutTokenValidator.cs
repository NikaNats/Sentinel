namespace Sentinel.Application.Common.Abstractions;

public interface ILogoutTokenValidator
{
    Task<string?> ValidateAndExtractSessionIdAsync(string logoutToken, CancellationToken ct);
}
