using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Middleware.Filters;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/auth")]
public sealed class AuthController(
    ITokenRefreshService refreshService,
    IAuthRevocationService revocationService,
    ISessionBlacklistCache blacklistCache) : ControllerBase
{
    public sealed record RefreshRequest(string RefreshToken);
    public sealed record RevokeRequest(string RefreshToken);

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
        var result = await refreshService.RefreshTokenAsync(request.RefreshToken, dpopProof, ct);

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
                Type = "/errors/token-theft-detected",
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

    private async Task TryBlacklistCurrentSessionAsync(CancellationToken ct)
    {
        var sid = User.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(sid))
        {
            await blacklistCache.BlacklistSessionAsync(sid, TimeSpan.FromMinutes(5), ct);
        }
    }
}
