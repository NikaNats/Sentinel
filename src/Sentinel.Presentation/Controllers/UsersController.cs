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
}
