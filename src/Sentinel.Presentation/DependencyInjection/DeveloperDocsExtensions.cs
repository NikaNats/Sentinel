using Scalar.AspNetCore;

namespace Sentinel.DependencyInjection;

internal static class DeveloperDocsExtensions
{
    public static IEndpointRouteBuilder MapDeveloperDocs(this IEndpointRouteBuilder app)
    {
        app.MapOpenApi();

        app.MapScalarApiReference("/scalar", options => options
                .WithTitle("Sentinel — FAPI 2.0 Security API")
                .WithTheme(ScalarTheme.Mars)
                .ForceDarkMode()
                .ExpandAllTags()
                .SortTagsAlphabetically()
                .SortOperationsByMethod()
                .ShowOperationId()
                .WithOpenApiRoutePattern("/openapi/v1.json")
                .AddPreferredSecuritySchemes("BearerAuth")
                .AddServer(new ScalarServer("https://localhost:5260", "Local Development"))
                .AddServer(new ScalarServer("https://api.sentinel.company", "Production"))
                .WithClassicLayout())
            .AllowAnonymous()
            .WithSummary("Scalar API Documentation")
            .WithDescription(
                "Interactive API Reference powered by Scalar – view endpoints, try requests with DPoP authentication")
            .WithTags("Documentation", "Developer Tools");

        return app;
    }
}
