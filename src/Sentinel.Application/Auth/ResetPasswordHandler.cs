using System.Security.Cryptography;
using System.Text;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;

namespace Sentinel.Application.Auth;

public sealed class ResetPasswordHandler(
    IResetTokenProvider resetTokenProvider,
    IKeycloakUserService keycloakUserService,
    IKeycloakProfileService keycloakProfileService,
    IJtiReplayCache replayCache,
    IAuthRevocationService authRevocationService)
{
    public async Task<ResetPasswordResult> HandleAsync(ResetPasswordRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return new ResetPasswordResult(false, "Token and new password are required.", "invalid_request");
        }

        var (isValid, email) = resetTokenProvider.ValidateToken(request.Token);
        if (!isValid || string.IsNullOrWhiteSpace(email))
        {
            return new ResetPasswordResult(false, "Invalid or expired token.", "invalid_or_expired_token");
        }

        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(request.Token));
        var cacheKey = $"consumed_token:{Convert.ToHexString(tokenHash)}";
        var isFirstUse = await replayCache.TryStoreIfNotExistsAsync(cacheKey, TimeSpan.FromMinutes(15), ct);
        if (!isFirstUse)
        {
            return new ResetPasswordResult(false, "Token already consumed.", "token_already_consumed");
        }

        var updated = await keycloakProfileService.UpdatePasswordAsync(email, request.NewPassword, ct);
        if (!updated)
        {
            return new ResetPasswordResult(false, "Failed to update password in Identity Store.",
                "password_update_failed");
        }

        var user = await keycloakUserService.GetUserByEmailAsync(email, ct);
        if (user is null)
        {
            return new ResetPasswordResult(false, "Failed to revoke active sessions.", "session_revoke_failed");
        }

        var revoked = await authRevocationService.RevokeAllSessionsAsync(user.Id, ct);
        if (!revoked)
        {
            return new ResetPasswordResult(false, "Failed to revoke active sessions.", "session_revoke_failed");
        }

        return new ResetPasswordResult(true, "Password updated successfully.");
    }
}
