using System.Security.Cryptography;
using System.Text;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Auth;
using Sentinel.Security.Abstractions.Identity;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Application.Auth;

public sealed class ResetPasswordHandler(
    IResetTokenProvider resetTokenProvider,
    IIdentityProvider identityProvider,
    IJtiReplayCache replayCache,
    IAuthRevocationService authRevocationService)
{
    /// <summary>
    /// Handles password reset with anti-replay token validation and session revocation.
    /// Validates token → checks replay cache → updates password → revokes sessions.
    /// </summary>
    public async Task<SecurityResult<ResetPasswordResult>> HandleAsync(
        ResetPasswordRequest request,
        CancellationToken ct)
    {
        // Step 1: Validate request
        var validationResult = ValidateRequest(request);
        if (!validationResult.IsSuccess)
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(validationResult.ErrorMessage!);
        }

        // Step 2: Validate token
        var (isTokenValid, email) = resetTokenProvider.ValidateToken(request.Token);
        if (!isTokenValid || string.IsNullOrWhiteSpace(email))
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(SecurityErrors.TokenInvalidMessage);
        }

        // Step 3: Check replay cache (prevent token reuse)
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(request.Token));
        var cacheKey = $"consumed_token:{Convert.ToHexString(tokenHash)}";
        var isFirstUse = await replayCache.TryStoreIfNotExistsAsync(cacheKey, TimeSpan.FromMinutes(15), ct);
        if (!isFirstUse)
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(SecurityErrors.TokenExpiredMessage);
        }

        // Step 4: Update password
        var passwordUpdated = await identityProvider.UpdatePasswordAsync(email, request.NewPassword, ct);
        if (!passwordUpdated)
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(
                SecurityErrors.InternalErrorMessage);
        }

        // Step 5: Get user for session revocation
        var user = await identityProvider.GetUserByEmailAsync(email, ct);
        if (user is null)
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(
                SecurityErrors.InternalErrorMessage);
        }

        // Step 6: Revoke all active sessions
        var sessionRevoked = await authRevocationService.RevokeAllSessionsAsync(user.Id, ct);
        if (!sessionRevoked)
        {
            return SecurityResultFactory.Failure<ResetPasswordResult>(
                SecurityErrors.InternalErrorMessage);
        }

        return SecurityResultFactory.Create(
            new ResetPasswordResult(true, "Password updated successfully."));
    }

    /// <summary>
    /// Validates the reset password request (token and new password).
    /// </summary>
    private static SecurityResult<ResetPasswordRequest> ValidateRequest(ResetPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return SecurityResultFactory.Failure<ResetPasswordRequest>(
                SecurityErrors.ValidationFailed);
        }

        return SecurityResultFactory.Create(request);
    }
}
