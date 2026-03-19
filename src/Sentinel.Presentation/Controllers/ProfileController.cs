using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Errors;
using System.Security.Claims;
using System.Text.Json;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/[controller]")]
[Authorize(Policy = Policies.ReadProfile)]
public sealed class ProfileController(IKeycloakProfileService keycloakProfileService) : ControllerBase
{
    public sealed record UpdateProfileRequest(string DisplayName);

    [HttpGet]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetProfile()
    {
        var sub = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        var displayName = User.FindFirstValue("name") ?? string.Empty;

        var rolesClaim = User.FindFirst("realm_access.roles")?.Value;
        var roles = Array.Empty<string>();
        if (!string.IsNullOrWhiteSpace(rolesClaim))
        {
            try
            {
                roles = JsonSerializer.Deserialize<string[]>(rolesClaim) ?? [];
            }
            catch (JsonException)
            {
                roles = [];
            }
        }

        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new ProblemDetails
            {
                Type = ErrorCodes.Unauthorized,
                Title = "Authentication required",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Ok(new ProfileResponse(sub, displayName, roles));
    }

    [HttpPut]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request, CancellationToken ct)
    {
        var sub = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(sub))
        {
            return Unauthorized(new ProblemDetails
            {
                Type = ErrorCodes.Unauthorized,
                Title = "Authentication required",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        if (string.IsNullOrWhiteSpace(request.DisplayName))
        {
            return BadRequest(new ProblemDetails
            {
                Type = ErrorCodes.InvalidRequest,
                Title = "Display name is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var updated = await keycloakProfileService.UpdateProfileAsync(sub, request.DisplayName, ct);
        if (!updated)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new ProblemDetails
            {
                Type = ErrorCodes.InternalServerError,
                Title = "Failed to update profile.",
                Status = StatusCodes.Status500InternalServerError
            });
        }

        var rolesClaim = User.FindFirst("realm_access.roles")?.Value;
        var roles = Array.Empty<string>();
        if (!string.IsNullOrWhiteSpace(rolesClaim))
        {
            try
            {
                roles = JsonSerializer.Deserialize<string[]>(rolesClaim) ?? [];
            }
            catch (JsonException)
            {
                roles = [];
            }
        }

        return Ok(new ProfileResponse(sub, request.DisplayName.Trim(), roles));
    }
}

public sealed record ProfileResponse(string Sub, string DisplayName, string[] Roles);
