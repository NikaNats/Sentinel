using Microsoft.AspNetCore.Routing;
using Sentinel.AspNetCore.Filters;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
///     Sentinel Framework Minimal API Extension Methods.
///     Provides clean, AOT-compatible endpoint mapping for consuming applications.
///     The host application controls the routing prefix entirely:
///     app.MapSentinelSecurity("api/v1/identity");
///     // Routes: POST /api/v1/identity/auth/refresh, /auth/change-password, etc.
///     Benefits over MVC Controllers:
///     - Zero reflection (AOT-compatible)
///     - Microsecond startup (no route table scan)
///     - Host app controls route prefix
///     - Minimal API filters replace MVC action filters
///     - Typed parameters with automatic validation
/// </summary>
public static class SentinelEndpointExtensions
{
    /// <summary>
    ///     Maps Sentinel Framework Security Endpoints (Auth, Token Exchange, SSF, Backchannel Logout) into the host
    ///     application.
    /// </summary>
    /// <param name="routes">The endpoint route builder.</param>
    /// <param name="prefix">The base URL prefix for security routes (e.g., "api/v1/identity"). Default is "v1".</param>
    /// <returns>The route group builder for fluent configuration.</returns>
    public static RouteGroupBuilder MapSentinelSecurity(this IEndpointRouteBuilder routes, string prefix = "v1")
    {
        var group = routes.MapGroup(prefix).WithTags("Sentinel Security API");

        group.MapAuthEndpoints();
        group.MapSsfEndpoints();
        group.MapTokenExchangeEndpoints();
        group.MapBackchannelLogoutEndpoints();

        return group;
    }

    /// <summary>
    ///     Adds Redis-backed idempotency enforcement to the endpoint.
    ///     Requires Idempotency-Key header (UUID format) and caches request state with 5-minute TTL.
    /// </summary>
    public static RouteHandlerBuilder RequireIdempotency(this RouteHandlerBuilder builder)
        => builder.AddEndpointFilter<IdempotencyFilter>();

    /// <summary>
    ///     Adds ACR step-up authorization check requiring acr3 (multi-factor auth).
    ///     Enforces authentication recency (default 5 minutes) per NIST SP 800-63B.
    ///     Returns WWW-Authenticate challenge on step-up required.
    /// </summary>
    public static RouteHandlerBuilder RequireAcrStepUp(this RouteHandlerBuilder builder, string requiredAcr = "acr3",
        TimeSpan? maxAuthAge = null)
        => builder.AddEndpointFilter(new AcrStepUpAuthorizationFilter(requiredAcr, maxAuthAge));
}
