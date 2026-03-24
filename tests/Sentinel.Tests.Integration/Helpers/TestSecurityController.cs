using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Sentinel.Tests.Integration.Helpers;

/// <summary>
/// Test controller for framework-level security testing.
/// This controller exists solely to test the framework's authorization, authentication, and cryptographic features.
/// It should NOT be used to test business logic (documents, finance, etc.).
/// </summary>
[ApiController]
[Route("v1/test")]
public class TestSecurityController : ControllerBase
{
    /// <summary>
    /// Protected endpoint requiring valid JWT + DPoP proof.
    /// Tests: Default authorization policy (authenticated user + acr claim present).
    /// </summary>
    [HttpGet("protected")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetProtected()
    {
        var sub = User.FindFirst("sub")?.Value;
        var acr = User.FindFirst("acr")?.Value;
        return Ok(new
        {
            message = "Secure endpoint accessed",
            subject = sub,
            assuranceLevel = acr
        });
    }

    /// <summary>
    /// Step-up authentication endpoint requiring ACR3 (highest assurance).
    /// Tests: AcrRequirement handler, RequestObjectJwt validation, DPoP binding to token.
    /// </summary>
    [HttpGet("step-up")]
    [Authorize(Policy = "RequireAcr3")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetStepUp()
    {
        var sub = User.FindFirst("sub")?.Value;
        return Ok(new
        {
            message = "High-assurance operation completed",
            subject = sub,
            assuranceLevel = "acr3"
        });
    }

    /// <summary>
    /// Endpoint testing DPoP proof validation and binding to access token.
    /// Tests: DPoP HTTP method binding, algorithm validation, replay attack prevention.
    /// </summary>
    [HttpPost("dpop-protected")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult PostDpopProtected([FromBody] object data)
    {
        // DPoP validation happens in middleware; if we reach here, proof is valid
        return Ok(new { message = "DPoP-bound operation successful", received = data });
    }

    /// <summary>
    /// Endpoint for testing scope-based authorization.
    /// Tests: ScopeAuthorizationHandler implementation.
    /// </summary>
    [HttpGet("scoped/{scope}")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetScoped(string scope)
    {
        var userScopes = User.FindFirst("scope")?.Value ?? "none";
        var hasScope = userScopes.Split(' ').Contains(scope);

        if (!hasScope)
        {
            return Forbid("Insufficient scope");
        }

        return Ok(new
        {
            message = $"Access granted for scope: {scope}",
            requestedScope = scope,
            userScopes = userScopes
        });
    }

    /// <summary>
    /// Echo endpoint for testing request/response integrity with cryptographic binding.
    /// Tests: Token payload validation, claim extraction.
    /// </summary>
    [HttpPost("echo")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Echo([FromBody] dynamic payload)
    {
        var sub = User.FindFirst("sub")?.Value;
        var iat = User.FindFirst("iat")?.Value;

        return Ok(new
        {
            message = "echoed",
            subject = sub,
            issuedAt = iat,
            echoedPayload = payload
        });
    }
}
