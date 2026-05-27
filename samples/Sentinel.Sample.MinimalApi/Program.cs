using Scalar.AspNetCore;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.Application.DependencyInjection;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.Extensions;
using Sentinel.Redis.Extensions;
using Sentinel.Sample.MinimalApi.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services
    .AddRedisSecurityCaches(builder.Configuration.GetSection("Sentinel:Redis"))
    .AddApplicationLayer()
    .AddKeycloakIntegration(builder.Configuration.GetSection("Sentinel:Keycloak"))
    .AddInfrastructureLayer(builder.Configuration);

builder.Services.AddSingleton<DocumentRepository>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler(errorApp =>
    {
        errorApp.Run(async context =>
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/problem+json";

            var traceId = context.TraceIdentifier.Replace("\"", "\\\"", StringComparison.Ordinal);
            var payload =
                $"{{\"type\":\"/errors/internal\",\"title\":\"Unexpected error\",\"detail\":\"An unexpected error occurred while processing the request.\",\"status\":500,\"traceId\":\"{traceId}\"}}";

            await context.Response.WriteAsync(payload);
        });
    });
}
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference("/docs");
}

const string securityPrefix = "api/system/security";
const string documentsPrefix = "api/v1/documents";
const string financePrefix = "api/v1/finance";
const string showcasePrefix = "api/v1/showcase";

app.MapGet("/", () => TypedResults.Ok(
    new SampleInfoResponse(
        Service: "Sentinel.Sample.MinimalApi",
        Docs: "/docs",
        Endpoints: new EndpointMap(
            Health: "/healthz",
            Security: $"/{securityPrefix}",
            Documents: $"/{documentsPrefix}",
            Finance: $"/{financePrefix}",
            Showcase: $"/{showcasePrefix}")))).AllowAnonymous();

app.MapGet("/healthz", () => TypedResults.Ok(new HealthResponse("ok", DateTimeOffset.UtcNow)))
    .AllowAnonymous();

app.MapSentinelSecurity(securityPrefix);
app.MapDocumentEndpoints(documentsPrefix);
app.MapFinanceEndpoints(financePrefix);
app.MapShowcaseEndpoints(showcasePrefix);

app.Run();

internal sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

internal sealed record EndpointMap(string Health, string Security, string Documents, string Finance, string Showcase);

internal sealed record HealthResponse(string Status, DateTimeOffset Utc);
