using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;
using Sentinel.Middleware;
using System.Threading.RateLimiting;

namespace Sentinel.DependencyInjection;

public static class ApiServiceCollectionExtensions
{
    public static IServiceCollection AddApiLayer(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            var identityLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                var sub = httpContext.User.FindFirst("sub")?.Value;
                var clientId = httpContext.User.FindFirst("client_id")?.Value ?? httpContext.User.FindFirst("azp")?.Value;
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                var key = !string.IsNullOrWhiteSpace(sub)
                    ? $"sub:{sub}|client:{clientId ?? "unknown"}"
                    : !string.IsNullOrWhiteSpace(clientId)
                        ? $"client:{clientId}"
                        : $"ip:{ip}";

                return RateLimitPartition.GetFixedWindowLimiter($"identity:{key}", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 2
                });
            });

            var ipLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter($"ip:{ip}", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 2
                });
            });

            options.GlobalLimiter = PartitionedRateLimiter.CreateChained(identityLimiter, ipLimiter);
        });

        services.AddExceptionHandler<GlobalExceptionHandler>();
        services.AddProblemDetails();
        services.AddControllers();
        services.AddHttpContextAccessor();

        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                if (document.Paths is null)
                {
                    return Task.CompletedTask;
                }

                document.Components ??= new OpenApiComponents();
                document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();

                document.Components.SecuritySchemes["DPoP"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "DPoP",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "FAPI 2.0 Demonstrating Proof-of-Possession (DPoP) bound access token."
                };

                document.Components.SecuritySchemes["mTLS"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "MutualTLS",
                    Description = "Mutual TLS (mTLS) client certificate authentication for Machine-to-Machine (M2M) endpoints."
                };

                return Task.CompletedTask;
            });
        });

        return services;
    }

    public static WebApplication UseApiLayer(this WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
        }

        app.UseMiddleware<SecurityHeadersMiddleware>();

        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseAuthentication();
        app.UseRateLimiter();
        app.UseMiddleware<DpopValidationMiddleware>();
        app.UseMiddleware<MtlsBindingMiddleware>();
        app.UseMiddleware<AcrValidationMiddleware>();
        app.UseAuthorization();

        app.MapPrometheusScrapingEndpoint();
        app.MapControllers();

        return app;
    }

    public static ConfigureWebHostBuilder AddApiWebHostDefaults(this ConfigureWebHostBuilder webHost)
    {
        webHost.ConfigureKestrel(options =>
        {
            options.ConfigureHttpsDefaults(httpsOptions =>
            {
                httpsOptions.ClientCertificateMode = ClientCertificateMode.DelayCertificate;
                httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;
            });
        });

        return webHost;
    }
}
