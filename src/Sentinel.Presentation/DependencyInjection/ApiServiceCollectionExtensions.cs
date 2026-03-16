using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
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

                var bucket = ResolveRateLimitBucket(httpContext);
                var permitLimit = ResolvePermitLimit(bucket);

                return RateLimitPartition.GetFixedWindowLimiter($"identity:{bucket}:{key}", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 2
                });
            });

            var ipLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var bucket = ResolveRateLimitBucket(httpContext);
                var permitLimit = ResolvePermitLimit(bucket);

                return RateLimitPartition.GetFixedWindowLimiter($"ip:{bucket}:{ip}", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
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

        return services;
    }

    public static WebApplication UseApiLayer(this WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();

        app.UseSecurityHeaders();

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

    private static string ResolveRateLimitBucket(HttpContext context)
    {
        var method = context.Request.Method;
        var path = context.Request.Path;

        if (path.StartsWithSegments("/v1/documents", StringComparison.OrdinalIgnoreCase))
        {
            if (HttpMethods.IsDelete(method))
            {
                return "documents-dangerous";
            }

            if (HttpMethods.IsPost(method) || HttpMethods.IsPut(method))
            {
                return "documents-write";
            }

            if (HttpMethods.IsGet(method))
            {
                return "documents-read";
            }
        }

        return "default";
    }

    private static int ResolvePermitLimit(string bucket)
    {
        return bucket switch
        {
            "documents-read" => 100,
            "documents-write" => 20,
            "documents-dangerous" => 10,
            _ => 100
        };
    }
}
