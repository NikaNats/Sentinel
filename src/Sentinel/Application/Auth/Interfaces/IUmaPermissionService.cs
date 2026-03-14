namespace Sentinel.Application.Auth.Interfaces;

public interface IUmaPermissionService
{
    Task<bool> HasAccessAsync(string accessToken, string resourceId, string scope, CancellationToken ct);
}
