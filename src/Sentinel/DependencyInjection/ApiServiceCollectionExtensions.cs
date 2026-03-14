using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.OpenApi;
using Sentinel.Middleware;

namespace Sentinel.DependencyInjection;

public static class ApiServiceCollectionExtensions
{
    public static IServiceCollection AddApiLayer(this IServiceCollection services)
    {
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
        app.UseRateLimiter();
        app.UseMiddleware<DpopValidationMiddleware>();
        app.UseMiddleware<ReplayCacheFailureMiddleware>();

        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseAuthentication();
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
