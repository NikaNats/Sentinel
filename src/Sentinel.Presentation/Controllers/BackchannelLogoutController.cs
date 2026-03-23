using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Auth;
using Sentinel.Keycloak;

namespace Sentinel.Presentation.Controllers;

[ApiController]
[Route("v1/auth")]
[ApiExplorerSettings(IgnoreApi = true)]
public sealed class BackchannelLogoutController(
    ILogoutTokenValidator validator,
    ISessionBlacklistCache blacklistCache,
    IOptions<KeycloakOptions> options,
    ILogger<BackchannelLogoutController> logger) : ControllerBase
{
    private readonly KeycloakOptions keycloakOptions = options.Value;

    [HttpPost("backchannel-logout")]
    [AllowAnonymous]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Logout([FromForm(Name = "logout_token")] string logoutToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(logoutToken))
        {
            return BadRequest();
        }

        var sessionId = await validator.ValidateAndExtractSessionIdAsync(logoutToken, ct);
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            logger.LogWarning("Invalid back-channel logout token received.");
            return BadRequest();
        }

        await blacklistCache.BlacklistSessionAsync(sessionId, keycloakOptions.ResolveSessionBlacklistTtl(), ct);
        return Ok();
    }
}
