using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Json;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/[controller]")]
[Authorize(Policy = "ReadProfile")]
public sealed class ProfileController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetProfile()
    {
        var sub = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        var displayName = User.FindFirstValue("name") ?? string.Empty;

        var rolesClaim = User.FindFirst("realm_access.roles")?.Value;
        var roles = string.IsNullOrWhiteSpace(rolesClaim)
            ? []
            : JsonSerializer.Deserialize<string[]>(rolesClaim) ?? [];

        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new ProblemDetails
            {
                Type = "/errors/unauthorized",
                Title = "Authentication required",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Ok(new ProfileResponse(sub, displayName, roles));
    }
}

public sealed record ProfileResponse(string Sub, string DisplayName, string[] Roles);
