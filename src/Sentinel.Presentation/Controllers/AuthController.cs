using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Errors;
using Sentinel.Infrastructure.Telemetry;
using Sentinel.Middleware.Filters;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/auth")]
public sealed class AuthController(
    ITokenRefreshService refreshService,
    IAuthRevocationService revocationService,
    IKeycloakProfileService keycloakProfileService,
    IPasswordStrengthValidator passwordStrengthValidator,
    ISessionBlacklistCache blacklistCache,
    IConfiguration configuration) : ControllerBase
{
    public sealed record RefreshRequest(string RefreshToken);
    public sealed record RevokeRequest(string RefreshToken);
    public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public sealed record TotpSetupRequest(string DeviceName);
    public sealed record TotpVerifyRequest(string Code);

    [HttpPost("refresh")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Refresh token is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var dpopProof = Request.Headers["DPoP"].ToString();
        var ipHash = SecurityContextHasher.HashIp(HttpContext);
        var result = await refreshService.RefreshTokenAsync(request.RefreshToken, dpopProof, ipHash, ct);

        if (result.IsSuccess)
        {
            return Ok(new
            {
                access_token = result.AccessToken,
                refresh_token = result.RefreshToken
            });
        }

        if (result.IsReuseDetected)
        {
            return Unauthorized(new ProblemDetails
            {
                Type = ErrorCodes.TokenTheftDetected,
                Title = "Session Terminated",
                Detail = "Security policy violation detected. Please log in again.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Unauthorized(new ProblemDetails
        {
            Title = "Invalid refresh token",
            Status = StatusCodes.Status401Unauthorized
        });
    }

    [HttpPost("change-password")]
    [Authorize]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Current and new passwords are required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized();
        }

        var loginIdentifier = User.FindFirst("preferred_username")?.Value
            ?? User.FindFirst("email")?.Value
            ?? sub;

        var currentPasswordValid = await keycloakProfileService.VerifyUserPasswordAsync(loginIdentifier, request.CurrentPassword, ct);
        if (!currentPasswordValid)
        {
            return BadRequest(new ProblemDetails
            {
                Type = ErrorCodes.InvalidCurrentPassword,
                Title = "Current password is invalid.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var passwordValidation = passwordStrengthValidator.Validate(request.NewPassword);
        if (!passwordValidation.IsValid)
        {
            return BadRequest(new ProblemDetails
            {
                Type = ErrorCodes.WeakPassword,
                Title = passwordValidation.Message ?? "Password does not meet complexity requirements.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var updated = await keycloakProfileService.UpdatePasswordAsync(loginIdentifier, request.NewPassword, ct);
        if (!updated)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Type = ErrorCodes.InternalServerError,
                Title = "Failed to update password.",
                Status = StatusCodes.Status500InternalServerError
            });
        }

        _ = await revocationService.RevokeAllSessionsAsync(sub, ct);
        return NoContent();
    }

    [HttpPost("logout")]
    [Authorize]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Logout([FromBody] RevokeRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Refresh token is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        await TryBlacklistCurrentSessionAsync(ct);

        await revocationService.RevokeCurrentSessionAsync(request.RefreshToken, ct);
        return NoContent();
    }

    [HttpGet("sessions")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetActiveSessions(CancellationToken ct)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new ProblemDetails
            {
                Type = ErrorCodes.Unauthorized,
                Title = "Authentication required",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        var sessions = await revocationService.GetActiveSessionsAsync(sub, ct);
        return Ok(sessions);
    }

    [HttpDelete("sessions/{sessionId}")]
    [Authorize]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeSession([FromRoute] string sessionId, CancellationToken ct)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new ProblemDetails
            {
                Type = ErrorCodes.Unauthorized,
                Title = "Authentication required",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return BadRequest(new ProblemDetails
            {
                Type = ErrorCodes.InvalidRequest,
                Title = "Session id is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var revoked = await revocationService.RevokeSessionAsync(sub, sessionId, ct);
        if (!revoked)
        {
            return NotFound();
        }

        return NoContent();
    }

    [HttpPost("logout-all")]
    [Authorize]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> GlobalLogout(CancellationToken ct)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized();
        }

        await TryBlacklistCurrentSessionAsync(ct);

        var success = await revocationService.RevokeAllSessionsAsync(sub, ct);
        if (!success)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Title = "Failed to process global logout.",
                Status = StatusCodes.Status500InternalServerError
            });
        }

        return NoContent();
    }

    [HttpDelete("account")]
    [Authorize]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> DeleteAccount(CancellationToken ct)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized();
        }

        await TryBlacklistCurrentSessionAsync(ct);
        _ = await revocationService.RevokeAllSessionsAsync(sub, ct);

        var deleted = await revocationService.DeleteAccountAsync(sub, ct);
        if (!deleted)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Title = "Failed to delete account.",
                Status = StatusCodes.Status500InternalServerError
            });
        }

        return NoContent();
    }

    [HttpPost("mfa/totp/setup")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    public IActionResult SetupTotp([FromBody] TotpSetupRequest request)
    {
        _ = request;
        return StatusCode(StatusCodes.Status501NotImplemented, BuildMfaNotConfiguredProblem());
    }

    [HttpPost("mfa/totp/verify")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    public IActionResult VerifyTotp([FromBody] TotpVerifyRequest request)
    {
        _ = request;
        return StatusCode(StatusCodes.Status501NotImplemented, BuildMfaNotConfiguredProblem());
    }

    [HttpDelete("mfa/totp")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    public IActionResult DeleteTotp()
    {
        return StatusCode(StatusCodes.Status501NotImplemented, BuildMfaNotConfiguredProblem());
    }

    [HttpGet("mfa/recovery-codes")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    public IActionResult GetRecoveryCodes()
    {
        return StatusCode(StatusCodes.Status501NotImplemented, BuildMfaNotConfiguredProblem());
    }

    [HttpPost("mfa/recovery-codes/regenerate")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    public IActionResult RegenerateRecoveryCodes()
    {
        return StatusCode(StatusCodes.Status501NotImplemented, BuildMfaNotConfiguredProblem());
    }

    private async Task TryBlacklistCurrentSessionAsync(CancellationToken ct)
    {
        var sid = User.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, ResolveSessionBlacklistTtl(configuration), ct);
        }
    }

    private static TimeSpan ResolveSessionBlacklistTtl(IConfiguration configuration)
    {
        var configuredSeconds = configuration.GetValue<int?>("Keycloak:SsoSessionMaxLifespanSeconds")
            ?? configuration.GetValue<int?>("Keycloak:SessionMaxLifespanSeconds")
            ?? 28_800;

        if (configuredSeconds <= 0)
        {
            configuredSeconds = 28_800;
        }

        return TimeSpan.FromSeconds(configuredSeconds);
    }

    private static ProblemDetails BuildMfaNotConfiguredProblem()
    {
        return new ProblemDetails
        {
            Type = ErrorCodes.MfaNotConfigured,
            Title = "MFA management endpoints are not configured yet.",
            Status = StatusCodes.Status501NotImplemented
        };
    }
}
