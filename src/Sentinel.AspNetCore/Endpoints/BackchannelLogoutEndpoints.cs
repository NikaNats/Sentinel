using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Keycloak;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
/// OpenID Connect Backchannel Logout (RFC 9413) Endpoints.
///
/// Implements server-initiated logout signaling for long-lived applications (web + mobile).
/// When user logs out from IdP, receives logout token POST that invalidates all user sessions.
/// Must be anonymous (endpoint doesn't authenticate caller, validates logout token JWT signature instead).
/// </summary>
internal static class BackchannelLogoutEndpoints
{
    public static void MapBackchannelLogoutEndpoints(this RouteGroupBuilder group)
    {
        var logoutGroup = group.MapGroup("/auth")
            .WithTags("OIDC Backchannel Logout")
            .ExcludeFromDescription(); // Backchannel endpoints are not documented in public API spec (RFC 9413)

        logoutGroup.MapPost("/backchannel-logout", ReceiveLogoutTokenAsync)
            .AllowAnonymous()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .WithName("BackchannelLogout");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Route Handler
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RFC 9413 POST /backchannel-logout endpoint.
    ///
    /// Validates incoming logout token and blacklists the identified session.
    /// Returns 200 OK on success (must not indicate token validation errors per RFC for security).
    /// </summary>
    private static async Task<IResult> ReceiveLogoutTokenAsync(
        [FromForm(Name = "logout_token")] string logoutToken,
        [FromServices] ILogoutTokenValidator validator,
        [FromServices] ISessionBlacklistCache blacklistCache,
        [FromServices] IOptions<KeycloakOptions> options,
        [FromServices] ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger(nameof(BackchannelLogoutEndpoints));

        if (string.IsNullOrWhiteSpace(logoutToken))
        {
            // RFC 9413: Return 400 only for malformed requests, not for invalid tokens
            return TypedResults.BadRequest();
        }

        try
        {
            var sessionId = await validator.ValidateAndExtractSessionIdAsync(logoutToken, ct);

            // RFC 9413: MUST handle invalid tokens silently (except malformed)
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                logger.LogWarning("Invalid backchannel logout token received. Token validation failed.");
                return TypedResults.Ok();
            }

            // Blacklist the session to force re-authentication on next access
            var keycloakOptions = options.Value;
            await blacklistCache.BlacklistSessionAsync(sessionId, keycloakOptions.ResolveSessionBlacklistTtl(), ct);

            logger.LogInformation("Session {SessionId} blacklisted via backchannel logout.", sessionId);
            return TypedResults.Ok();
        }
#pragma warning disable CA1031 // Do not catch general exception types
        // RFC 9413 Section 4: Backchannel logout endpoints MUST return 200 even on errors
        // to prevent attackers from using errors to determine valid session IDs
        catch (Exception ex)
        {
            // RFC 9413: Log internal errors but always return 200 to avoid leaking validation details
            logger.LogError(ex, "Unexpected error processing backchannel logout token.");
            return TypedResults.Ok();
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }
}
