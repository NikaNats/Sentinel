using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Sentinel.Keycloak.Extensions;

/// <summary>
///     Single binding point for <see cref="KeycloakOptions" />, shared by every Keycloak registration entry point
///     so hosts configure Keycloak once.
/// </summary>
internal static class KeycloakOptionsRegistration
{
    internal static OptionsBuilder<KeycloakOptions> AddKeycloakOptions(this IServiceCollection services)
    {
        // TryAddEnumerable dedupes by implementation type, so calling both AddKeycloak and
        // AddKeycloakIntegration binds the options once.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<KeycloakOptions>, KeycloakOptionsSetup>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IOptionsChangeTokenSource<KeycloakOptions>, KeycloakOptionsChangeTokenSource>());
        return services.AddOptions<KeycloakOptions>();
    }

    /// <summary>
    ///     Binds <see cref="KeycloakOptions.LegacySectionName" /> first and <see cref="KeycloakOptions.SectionName" />
    ///     over it: keys under <c>Keycloak</c> win, and <c>Sentinel:Keycloak</c> only fills keys left unset.
    /// </summary>
    private sealed class KeycloakOptionsSetup(IConfiguration configuration) : IConfigureOptions<KeycloakOptions>
    {
        public void Configure(KeycloakOptions options)
        {
            configuration.GetSection(KeycloakOptions.LegacySectionName).Bind(options);
            configuration.GetSection(KeycloakOptions.SectionName).Bind(options);
        }
    }

    private sealed class KeycloakOptionsChangeTokenSource(IConfiguration configuration)
        : ConfigurationChangeTokenSource<KeycloakOptions>(configuration);
}
