using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/users")]
public sealed class UsersController(
    RegisterUserHandler registerUserHandler,
    ForgotPasswordHandler forgotPasswordHandler,
    ResetPasswordHandler resetPasswordHandler,
    ResendVerificationHandler resendVerificationHandler,
    IEmailVerificationTokenStore verificationTokenStore,
    IKeycloakAdminService keycloakAdminService) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting("registration_policy")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request, CancellationToken ct)
    {
        var ipHash = SecurityContextHasher.HashIp(HttpContext);
        var result = await registerUserHandler.HandleAsync(request, ipHash, ct);

        if (!result.IsSuccess)
        {
            return BadRequest(new ProblemDetails
            {
                Title = result.Message,
                Status = StatusCodes.Status400BadRequest,
                Type = result.ErrorCode is null ? null : $"/errors/{result.ErrorCode}"
            });
        }

        return Ok(new { result.Message });
    }

    [HttpPost("verify-email")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail([FromQuery] string token, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Token is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var keycloakUserId = await verificationTokenStore.ConsumeAsync(token, ct);
        if (string.IsNullOrWhiteSpace(keycloakUserId))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Invalid or expired verification token.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var updated = await keycloakAdminService.SetEmailVerifiedAsync(keycloakUserId, verified: true, ct);
        if (!updated)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "Unable to verify email at this time.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        return Ok(new { Message = "Email verified." });
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [EnableRateLimiting("forgot_password_policy")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken ct)
    {
        await forgotPasswordHandler.HandleAsync(request, ct);
        return Accepted();
    }

    [HttpPost("resend-verification")]
    [AllowAnonymous]
    [EnableRateLimiting("resend_verification_policy")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationRequest request, CancellationToken ct)
    {
        await resendVerificationHandler.HandleAsync(request, ct);
        return Accepted();
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken ct)
    {
        var result = await resetPasswordHandler.HandleAsync(request, ct);
        if (result.IsSuccess)
        {
            return Ok(new { result.Message });
        }

        if (result.ErrorCode is "invalid_request" or "invalid_or_expired_token" or "token_already_consumed")
        {
            return BadRequest(new ProblemDetails
            {
                Title = result.Message,
                Status = StatusCodes.Status400BadRequest,
                Type = $"/errors/{result.ErrorCode}"
            });
        }

        return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
        {
            Title = result.Message,
            Status = StatusCodes.Status500InternalServerError,
            Type = result.ErrorCode is null ? null : $"/errors/{result.ErrorCode}"
        });
    }
}
