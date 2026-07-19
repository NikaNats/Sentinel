using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Rar;
using Sentinel.SdJwt;

namespace Sentinel.Sample.MinimalApi.Endpoints;

#pragma warning disable CA1859

internal static class ShowcaseEndpoints
{
    public static void MapShowcaseEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization()
            .WithTags("Showcase");

        group.MapGet("/security-context", GetSecurityContext)
            .WithName($"GetSecurityContext:{prefix}")
            .Produces<SecurityContextDto>()
            .Produces(StatusCodes.Status401Unauthorized);

        group.MapGet("/profile", GetProfileAsync)
            .AllowAnonymous()
            .RequireRateLimiting("profile")
            .WithName($"GetProfile:{prefix}")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden);

        group.MapGet("/test/protected", GetProtected)
            .RequireRateLimiting("profile")
            .WithName($"GetProtected:{prefix}")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized);

        group.MapGet("/test/step-up", GetStepUp)
            .RequireAuthorization(Policies.RequireAcr3)
            .WithName($"GetStepUp:{prefix}")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized);
    }

    private static IResult GetSecurityContext(HttpContext context)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        var acr = context.User.FindFirst("acr")?.Value ?? "unknown";
        var dpopJkt = context.Items.TryGetValue("dpop.jkt", out var value)
            ? value?.ToString() ?? "missing"
            : "missing";

        var authorizationDetailsCount = context.User.GetAuthorizationDetails().Length;

        return TypedResults.Ok(new SecurityContextDto(
            sub,
            acr,
            dpopJkt,
            authorizationDetailsCount,
            context.TraceIdentifier));
    }

    private static async Task<IResult> GetProfileAsync(
        HttpContext context,
        [FromServices] SdJwtPresenter presenter,
        CancellationToken cancellationToken)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var bearerToken = authHeader["Bearer ".Length..].Trim();
            if (bearerToken.Contains('~', StringComparison.Ordinal))
            {
                var verification = await presenter.VerifyPresentationAsync(
                    bearerToken,
                    "sentinel-api",
                    null,
                    cancellationToken);

                if (!verification.IsValid || verification.Principal is null)
                {
                    return TypedResults.Unauthorized();
                }

                var claims = verification.Principal.Claims
                    .GroupBy(c => c.Type, StringComparer.Ordinal)
                    .ToDictionary(
                        group => group.Key,
                        group => group.Last().Value,
                        StringComparer.Ordinal);

                return TypedResults.Ok(claims);
            }
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            return TypedResults.Unauthorized();
        }

        if (!HasScope(context.User, "profile"))
        {
            return TypedResults.Forbid();
        }

        return TypedResults.Ok(new
        {
            sub = context.User.FindFirst("sub")?.Value,
            acr = context.User.FindFirst("acr")?.Value
        });
    }

    private static IResult GetProtected(HttpContext context) =>
        TypedResults.Ok(new
        {
            subject = context.User.FindFirst("sub")?.Value,
            assuranceLevel = context.User.FindFirst("acr")?.Value
        });

    private static IResult GetStepUp(HttpContext context) =>
        TypedResults.Ok(new
        {
            subject = context.User.FindFirst("sub")?.Value,
            assuranceLevel = "acr3"
        });

    private static bool HasScope(ClaimsPrincipal user, string scope)
    {
        var scopeClaim = user.FindFirst("scope")?.Value;
        if (string.IsNullOrWhiteSpace(scopeClaim))
        {
            return false;
        }

        return scopeClaim
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(scope, StringComparer.Ordinal);
    }
}

#pragma warning restore CA1859

public sealed record SecurityContextDto(
    string Subject,
    string Acr,
    string DpopJkt,
    int AuthorizationDetailsCount,
    string TraceId);
