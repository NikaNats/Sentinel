using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Auth.Rar;

namespace Sentinel.Sample.MinimalApi.Endpoints;

internal static class ShowcaseEndpoints
{
    public static void MapShowcaseEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization()
            .WithTags("Showcase");

        group.MapGet("/security-context", GetSecurityContext)
            .WithName("GetSecurityContext")
            .Produces<SecurityContextDto>(StatusCodes.Status200OK)
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
            Subject: sub,
            Acr: acr,
            DpopJkt: dpopJkt,
            AuthorizationDetailsCount: authorizationDetailsCount,
            TraceId: context.TraceIdentifier));
    }
}

public sealed record SecurityContextDto(
    string Subject,
    string Acr,
    string DpopJkt,
    int AuthorizationDetailsCount,
    string TraceId);
