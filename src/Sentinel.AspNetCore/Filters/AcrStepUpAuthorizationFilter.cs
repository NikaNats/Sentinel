using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.AspNetCore.Filters;

/// <summary>
///     Native AOT-compatible Endpoint Filter for ACR (Authentication Context Class) Step-Up validation.
///     NIST SP 800-63B mandates that high-security operations (password change, sensitive authorizations)
///     require recent strong authentication (ACR3 = multi-factor).
///     This filter enforces:
///     1. User has acr3 claim in current token
///     2. Authentication happened within the last 5 minutes
///     3. Returns proper WWW-Authenticate challenge if step-up required
/// </summary>
public sealed class AcrStepUpAuthorizationFilter : IEndpointFilter
{
    private readonly TimeSpan _maxAuthAge;
    private readonly string _requiredAcr;

    public AcrStepUpAuthorizationFilter(string requiredAcr = "acr3", TimeSpan? maxAuthAge = null)
    {
        _requiredAcr = requiredAcr;
        _maxAuthAge = maxAuthAge ?? TimeSpan.FromMinutes(5);
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;
        var logger = httpContext.RequestServices.GetService<ILogger<AcrStepUpAuthorizationFilter>>();

        // Check if user is authenticated
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            return TypedResults.Unauthorized();
        }

        var sub = httpContext.User.FindFirst("sub")?.Value;
        var currentAcr = httpContext.User.FindFirst("acr")?.Value;

        // Verify ACR level
        if (!string.Equals(currentAcr, _requiredAcr, StringComparison.OrdinalIgnoreCase))
        {
            logger?.LogWarning(
                "Step-up required for user {Subject}. Current ACR: {CurrentAcr}, Required: {RequiredAcr}",
                sub, currentAcr, _requiredAcr);

            // RFC 6750 Section 3: Return WWW-Authenticate challenge with acr_values
            httpContext.Response.Headers.Append("WWW-Authenticate",
                $"Bearer error=\"insufficient_user_authentication\", error_description=\"Step-up authentication required\", acr_values=\"{_requiredAcr}\", max_age=\"{(int)_maxAuthAge.TotalSeconds}\"");

            return TypedResults.Problem(
                type: "/errors/insufficient-acr",
                title: "Recent strong authentication required",
                detail: $"This operation requires a recent {_requiredAcr} authentication.",
                statusCode: StatusCodes.Status401Unauthorized,
                extensions: new Dictionary<string, object?>
                {
                    ["required_acr"] = _requiredAcr,
                    ["max_age"] = (int)_maxAuthAge.TotalSeconds
                });
        }

        // Verify authentication recency
        var authTimeClaim = httpContext.User.FindFirst("auth_time")?.Value;
        if (!long.TryParse(authTimeClaim, out var authTimeUnix))
        {
            logger?.LogWarning("Invalid auth_time claim for user {Subject}.", sub);
            return TypedResults.Unauthorized();
        }

        var authTime = DateTimeOffset.FromUnixTimeSeconds(authTimeUnix);
        var timeProvider = httpContext.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;
        var authAge = timeProvider.GetUtcNow() - authTime;

        if (authAge > _maxAuthAge)
        {
            logger?.LogWarning("Authentication too old for user {Subject}. Age: {AuthAge}", sub, authAge);

            httpContext.Response.Headers.Append("WWW-Authenticate",
                $"Bearer error=\"insufficient_user_authentication\", error_description=\"Recent authentication required\", acr_values=\"{_requiredAcr}\", max_age=\"{(int)_maxAuthAge.TotalSeconds}\"");

            return TypedResults.Problem(
                type: "/errors/session-too-old",
                title: "Recent authentication required",
                detail:
                $"This operation requires authentication within the last {(int)_maxAuthAge.TotalMinutes} minutes.",
                statusCode: StatusCodes.Status401Unauthorized,
                extensions: new Dictionary<string, object?>
                {
                    ["required_acr"] = _requiredAcr,
                    ["max_age"] = (int)_maxAuthAge.TotalSeconds
                });
        }

        return await next(context);
    }
}
