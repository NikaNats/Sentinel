using System.Security.Authentication;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Sentinel.AspNetCore.Extensions;
using Sentinel.AspNetCore.Middleware;
using Sentinel.Auth.Authorization;
using Sentinel.Middleware;
using Sentinel.Presentation.Middleware;

namespace Sentinel.DependencyInjection;

public static class ApiServiceCollectionExtensions
{
    public static IServiceCollection AddApiLayer(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();
        services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
        services.AddScoped<IAuthorizationHandler, UmaResourceAuthorizationHandler>();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddFixedWindowLimiter("registration_policy", registrationOptions =>
            {
                registrationOptions.Window = TimeSpan.FromMinutes(15);
                registrationOptions.PermitLimit = 3;
                registrationOptions.QueueLimit = 0;
            });
            options.AddFixedWindowLimiter("forgot_password_policy", forgotPasswordOptions =>
            {
                forgotPasswordOptions.Window = TimeSpan.FromMinutes(15);
                forgotPasswordOptions.PermitLimit = 2;
                forgotPasswordOptions.QueueLimit = 0;
            });
            options.AddFixedWindowLimiter("resend_verification_policy", resendVerificationOptions =>
            {
                resendVerificationOptions.Window = TimeSpan.FromHours(1);
                resendVerificationOptions.PermitLimit = 3;
                resendVerificationOptions.QueueLimit = 0;
            });

            var identityLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                var sub = httpContext.User.FindFirst("sub")?.Value;
                var clientId = httpContext.User.FindFirst("client_id")?.Value ??
                               httpContext.User.FindFirst("azp")?.Value;
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                var key = !string.IsNullOrWhiteSpace(sub)
                    ? $"sub:{sub}|client:{clientId ?? "unknown"}"
                    : !string.IsNullOrWhiteSpace(clientId)
                        ? $"client:{clientId}"
                        : $"ip:{ip}";

                var bucket = ResolveRateLimitBucket(httpContext);
                var permitLimit = ResolvePermitLimit(bucket);

                return RateLimitPartition.GetFixedWindowLimiter($"identity:{bucket}:{key}", _ =>
                    new FixedWindowRateLimiterOptions
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

                return RateLimitPartition.GetFixedWindowLimiter($"ip:{bucket}:{ip}", _ =>
                    new FixedWindowRateLimiterOptions
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

        // Register Sentinel ASP.NET Core middleware and filters
        services.AddSentinelAspNetCore().AddAll();

        return services;
    }

    public static WebApplication UseApiLayer(this WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();

        Sentinel.AspNetCore.Middleware.SecurityHeadersMiddlewareExtensions.UseSecurityHeaders(app);

        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseMiddleware<Sentinel.AspNetCore.Middleware.CorrelationIdMiddleware>();

        app.UseAuthentication();
        app.UseMiddleware<Sentinel.AspNetCore.Middleware.DpopValidationMiddleware>();
        app.UseMiddleware<Sentinel.AspNetCore.Middleware.MtlsBindingMiddleware>();
        app.UseMiddleware<Sentinel.Middleware.AcrValidationMiddleware>();
        app.UseRateLimiter();
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
                httpsOptions.SslProtocols = SslProtocols.Tls13;
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
