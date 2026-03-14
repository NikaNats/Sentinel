using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/auth")]
public sealed class AuthController(ITokenRefreshService refreshService) : ControllerBase
{
    public sealed record RefreshRequest(string RefreshToken);

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
}
