using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.Security.Diagnostics;

namespace Sentinel.AspNetCore.Infrastructure;

/// <summary>
///     Extensions for configuring Kestrel certificate hot reload.
/// </summary>
public static class KestrelCertificateReloaderExtensions
{
    /// <summary>
    ///     Configures Kestrel to use the certificate reloader for HTTPS endpoints.
    ///     Reads configuration from the "Kestrel:CertificateReloader" section.
    /// </summary>
    public static IServiceCollection AddKestrelCertificateReloader(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<KestrelCertificateReloaderOptions>()
            .BindConfiguration(KestrelCertificateReloaderOptions.SectionName)
            .Validate(opts => !string.IsNullOrWhiteSpace(opts.Path) && File.Exists(opts.Path),
                "Certificate file must exist at the configured path.")
            .ValidateOnStart();

        services.AddSingleton<KestrelCertificateReloader>();

        return services;
    }

    /// <summary>
    ///     Configures Kestrel to use the certificate reloader's current certificate
    ///     for all HTTPS endpoints via ServerCertificateSelector.
    /// </summary>
    public static IWebHostBuilder UseKestrelCertificateReloader(
        this IWebHostBuilder builder)
    {
        return builder.ConfigureServices(services =>
        {
            services.AddSingleton(sp =>
            {
                var reloader = sp.GetRequiredService<KestrelCertificateReloader>();
                return new ConfigureKestrelOptions(reloader);
            });
        });
    }

    private sealed class ConfigureKestrelOptions : IConfigureOptions<KestrelServerOptions>
    {
        private readonly KestrelCertificateReloader _reloader;

        public ConfigureKestrelOptions(KestrelCertificateReloader reloader)
        {
            _reloader = reloader;
        }

        public void Configure(KestrelServerOptions options)
        {
            options.ConfigureHttpsDefaults(httpsOptions =>
            {
                httpsOptions.ServerCertificateSelector = (_, _) => _reloader.CurrentCertificate;
            });
        }
    }
}