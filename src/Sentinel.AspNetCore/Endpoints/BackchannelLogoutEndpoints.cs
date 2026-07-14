using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Keycloak;
using Sentinel.Security.Abstractions.Exceptions;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
///     OpenID Connect Backchannel Logout (RFC 9413) Endpoints.
///     Implements server-initiated logout signaling for long-lived applications (web + mobile).
///     When user logs out from IdP, receives logout token POST that invalidates all user sessions.
///     Must be anonymous (endpoint doesn't authenticate caller, validates logout token JWT signature instead).
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
    ///     RFC 9413 POST /backchannel-logout endpoint.
    ///     Validates incoming logout token and blacklists the identified session.
    ///     Returns 200 OK on success (must not indicate token validation errors per RFC for security).
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
            return TypedResults.BadRequest();
        }

        try
        {
            var sessionId = await validator.ValidateAndExtractSessionIdAsync(logoutToken, ct);

            if (string.IsNullOrWhiteSpace(sessionId))
            {
                logger.LogWarning("Invalid backchannel logout token received. Token validation failed.");
                return TypedResults.Ok();
            }

            var keycloakOptions = options.Value;
            await blacklistCache.BlacklistSessionAsync(sessionId, keycloakOptions.ResolveSessionBlacklistTtl(), ct);

            logger.LogInformation("Session blacklisted via backchannel logout.");
            return TypedResults.Ok();
        }
        catch (SecurityInfrastructureException ex)
        {
            logger.LogError(ex, "Backchannel logout could not persist revocation state.");
            return TypedResults.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return TypedResults.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
#pragma warning disable CA1031
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error processing backchannel logout token.");
            return TypedResults.Ok();
        }
#pragma warning restore CA1031
    }
}
