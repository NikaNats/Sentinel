using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Common.Abstractions;
using Sentinel.AspNetCore.Errors;
using Sentinel.AspNetCore.Telemetry;
using Sentinel.Keycloak;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
///     Auth Endpoints - Minimal API equivalents of the legacy AuthController.
///     All endpoints are AOT-compatible with zero reflection.
/// </summary>
internal static class AuthEndpoints
{
    public static void MapAuthEndpoints(this RouteGroupBuilder group)
    {
        var authGroup = group.MapGroup("/auth").WithTags("Authentication");

        // Token Refresh (AllowAnonymous, DPoP-bound for replay protection)
        authGroup.MapPost("/refresh", RefreshTokenAsync)
            .AllowAnonymous()
            .WithName("RefreshToken")
            .Produces(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        // Change Password (Require ACR3 step-up + idempotency)
        authGroup.MapPost("/change-password", ChangePasswordAsync)
            .RequireAuthorization()
            .RequireAcrStepUp("acr3", TimeSpan.FromMinutes(5))
            .RequireIdempotency()
            .WithName("ChangePassword")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        // Logout Current Session
        authGroup.MapPost("/logout", LogoutAsync)
            .RequireAuthorization()
            .RequireIdempotency()
            .WithName("Logout")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        // Get Active Sessions
        authGroup.MapGet("/sessions", GetActiveSessionsAsync)
            .RequireAuthorization()
            .WithName("GetActiveSessions")
            .Produces(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        // Revoke Session by ID
        authGroup.MapDelete("/sessions/{sessionId}", RevokeSessionAsync)
            .RequireAuthorization()
            .RequireIdempotency()
            .WithName("RevokeSession")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        // Global Logout - All Sessions + Device Tokens
        authGroup.MapPost("/logout-all", GlobalLogoutAsync)
            .RequireAuthorization()
            .RequireIdempotency()
            .WithName("GlobalLogout")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        // Account Deletion (Soft Delete + Revoke All Sessions)
        authGroup.MapDelete("/account", DeleteAccountAsync)
            .RequireAuthorization()
            .RequireIdempotency()
            .WithName("DeleteAccount")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        // MFA Endpoints (501 Not Implemented - reserved for future)
        authGroup.MapPost("/mfa/totp/setup", SetupTotpAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status501NotImplemented);

        authGroup.MapPost("/mfa/totp/verify", VerifyTotpAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status501NotImplemented);

        authGroup.MapDelete("/mfa/totp", DeleteTotpAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status501NotImplemented);

        authGroup.MapGet("/mfa/recovery-codes", GetRecoveryCodesAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status501NotImplemented);

        authGroup.MapPost("/mfa/recovery-codes/regenerate", RegenerateRecoveryCodesAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status501NotImplemented);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Route Handlers - AOT-Compatible Endpoint Logic
    // ─────────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> RefreshTokenAsync(
        [FromBody] RefreshRequest request,
        [FromHeader(Name = "DPoP")] string? dpopProof,
        [FromServices] ITokenRefreshService refreshService,
        HttpContext context,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return TypedResults.Problem(
                "Refresh token is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var dpop = dpopProof ?? string.Empty;
        var ipHash = SecurityContextHasher.HashIp(context);
        var result = await refreshService.RefreshTokenAsync(request.RefreshToken, dpop, ipHash, ct);

        if (result.IsSuccess)
        {
            return TypedResults.Ok(new
            {
                access_token = result.AccessToken,
                refresh_token = result.RefreshToken
            });
        }

        if (result.IsReuseDetected)
        {
            return TypedResults.Problem(
                type: ErrorCodes.TokenTheftDetected,
                title: "Session Terminated",
                detail: "Security policy violation detected. Please log in again.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return TypedResults.Problem(
            "Invalid refresh token",
            statusCode: StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> ChangePasswordAsync(
        [FromBody] ChangePasswordRequest request,
        [FromServices] IIdentityProvider identityProvider,
        [FromServices] IPasswordStrengthValidator passwordStrengthValidator,
        [FromServices] IAuthRevocationService revocationService,
        [FromServices] ISessionBlacklistCache blacklistCache,
        [FromServices] IOptions<KeycloakOptions> keycloakOptions,
        ClaimsPrincipal user,
        HttpContext context,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return TypedResults.Problem(
                "New password is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var sub = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        var loginIdentifier = user.FindFirst("preferred_username")?.Value
                              ?? user.FindFirst("email")?.Value
                              ?? sub;

        var passwordValidation = passwordStrengthValidator.Validate(request.NewPassword);
        if (!passwordValidation.IsValid)
        {
            return TypedResults.Problem(
                type: ErrorCodes.WeakPassword,
                title: passwordValidation.Error ?? "Password does not meet complexity requirements.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var updated = await identityProvider.UpdatePasswordAsync(loginIdentifier, request.NewPassword, ct);
        if (!updated)
        {
            return TypedResults.Problem(
                type: ErrorCodes.InternalServerError,
                title: "Failed to update password.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        // Revoke all other sessions after password change for security
        _ = await revocationService.RevokeAllSessionsAsync(sub, ct);

        // Blacklist current session too
        var sid = user.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, keycloakOptions.Value.ResolveSessionBlacklistTtl(), ct);
        }

        return TypedResults.NoContent();
    }

    private static async Task<IResult> LogoutAsync(
        [FromBody] RevokeRequest request,
        [FromServices] IAuthRevocationService revocationService,
        [FromServices] ISessionBlacklistCache blacklistCache,
        [FromServices] IOptions<KeycloakOptions> options,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return TypedResults.Problem(
                "Refresh token is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Blacklist current session
        var keycloakOptions = options.Value;
        var sid = user.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, keycloakOptions.ResolveSessionBlacklistTtl(), ct);
        }

        await revocationService.RevokeCurrentSessionAsync(request.RefreshToken, ct);
        return TypedResults.NoContent();
    }

    private static async Task<IResult> GetActiveSessionsAsync(
        [FromServices] IAuthRevocationService revocationService,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        var sub = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Problem(
                type: ErrorCodes.Unauthorized,
                title: "Authentication required",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var sessions = await revocationService.GetActiveSessionsAsync(sub, ct);
        return TypedResults.Ok(sessions);
    }

    private static async Task<IResult> RevokeSessionAsync(
        [FromRoute] string sessionId,
        [FromServices] IAuthRevocationService revocationService,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        var sub = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Problem(
                type: ErrorCodes.Unauthorized,
                title: "Authentication required",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return TypedResults.Problem(
                type: ErrorCodes.InvalidRequest,
                detail: "Session id is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var revoked = await revocationService.RevokeSessionAsync(sub, sessionId, ct);
        if (!revoked)
        {
            return TypedResults.NotFound();
        }

        return TypedResults.NoContent();
    }

    private static async Task<IResult> GlobalLogoutAsync(
        [FromServices] IAuthRevocationService revocationService,
        [FromServices] ISessionBlacklistCache blacklistCache,
        [FromServices] IOptions<KeycloakOptions> options,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        var sub = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        // Blacklist current session
        var keycloakOptions = options.Value;
        var sid = user.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, keycloakOptions.ResolveSessionBlacklistTtl(), ct);
        }

        var success = await revocationService.RevokeAllSessionsAsync(sub, ct);
        if (!success)
        {
            return TypedResults.Problem(
                type: ErrorCodes.InternalServerError,
                title: "Failed to process global logout.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        return TypedResults.NoContent();
    }

    private static async Task<IResult> DeleteAccountAsync(
        [FromServices] IAuthRevocationService revocationService,
        [FromServices] ISessionBlacklistCache blacklistCache,
        [FromServices] IOptions<KeycloakOptions> options,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        var sub = user.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        // Blacklist current session
        var keycloakOptions = options.Value;
        var sid = user.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, keycloakOptions.ResolveSessionBlacklistTtl(), ct);
        }

        // Revoke all other sessions
        _ = await revocationService.RevokeAllSessionsAsync(sub, ct);

        // Perform soft delete
        var deleted = await revocationService.DeleteAccountAsync(sub, ct);
        if (!deleted)
        {
            return TypedResults.Problem(
                type: ErrorCodes.InternalServerError,
                title: "Failed to delete account.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        return TypedResults.NoContent();
    }

    // MFA Endpoints - 501 Not Implemented (reserved for future phases)

    private static Task<IResult> SetupTotpAsync(
        [FromBody] TotpSetupRequest request)
    {
        _ = request;
        return Task.FromResult<IResult>(TypedResults.StatusCode(StatusCodes.Status501NotImplemented)
            as IResult ?? TypedResults.Problem(
            type: ErrorCodes.MfaNotConfigured,
            title: "MFA management endpoints are not configured yet.",
            statusCode: StatusCodes.Status501NotImplemented));
    }

    private static Task<IResult> VerifyTotpAsync(
        [FromBody] TotpVerifyRequest request)
    {
        _ = request;
        return Task.FromResult<IResult>(TypedResults.StatusCode(StatusCodes.Status501NotImplemented)
            as IResult ?? TypedResults.Problem(
            type: ErrorCodes.MfaNotConfigured,
            title: "MFA management endpoints are not configured yet.",
            statusCode: StatusCodes.Status501NotImplemented));
    }

    private static Task<IResult> DeleteTotpAsync()
    {
        return Task.FromResult<IResult>(TypedResults.StatusCode(StatusCodes.Status501NotImplemented)
            as IResult ?? TypedResults.Problem(
            type: ErrorCodes.MfaNotConfigured,
            title: "MFA management endpoints are not configured yet.",
            statusCode: StatusCodes.Status501NotImplemented));
    }

    private static Task<IResult> GetRecoveryCodesAsync()
    {
        return Task.FromResult<IResult>(TypedResults.StatusCode(StatusCodes.Status501NotImplemented)
            as IResult ?? TypedResults.Problem(
            type: ErrorCodes.MfaNotConfigured,
            title: "MFA management endpoints are not configured yet.",
            statusCode: StatusCodes.Status501NotImplemented));
    }

    private static Task<IResult> RegenerateRecoveryCodesAsync()
    {
        return Task.FromResult<IResult>(TypedResults.StatusCode(StatusCodes.Status501NotImplemented)
            as IResult ?? TypedResults.Problem(
            type: ErrorCodes.MfaNotConfigured,
            title: "MFA management endpoints are not configured yet.",
            statusCode: StatusCodes.Status501NotImplemented));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // DTOs
    // ─────────────────────────────────────────────────────────────────────────────

    public sealed record RefreshRequest(string RefreshToken);

    public sealed record RevokeRequest(string RefreshToken);

    public sealed record ChangePasswordRequest(string NewPassword);

    public sealed record TotpSetupRequest(string DeviceName);

    public sealed record TotpVerifyRequest(string Code);
}
