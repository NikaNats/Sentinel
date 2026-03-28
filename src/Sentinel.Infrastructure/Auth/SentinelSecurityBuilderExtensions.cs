using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Sentinel.Application.Auth.Models;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Security.Abstractions.DependencyInjection;

// using Sentinel.Infrastructure.Notifications;

namespace Sentinel.Infrastructure.Auth;

public sealed class SentinelSecurityOptions
{
    public string Authority { get; set; } = string.Empty;
}

public sealed class SocialFederationBuilder
{
    internal SocialFederationOptions Options { get; } = new();

    public SocialFederationBuilder AddGoogle(Action<GoogleFederationOptions> configure)
    {
        configure(Options.Google);
        Options.Google.Enabled = true;
        return this;
    }

    public SocialFederationBuilder AddGitHub(Action<GitHubFederationOptions> configure)
    {
        configure(Options.GitHub);
        Options.GitHub.Enabled = true;
        return this;
    }
}

public static class SentinelSecurityBuilderExtensions
{
    public static ISentinelSecurityBuilder AddSentinelSecurity(this IServiceCollection services,
        Action<SentinelSecurityOptions> configure)
    {
        _ = services.Configure(configure);
        return new SentinelSecurityBuilder(services);
    }

    public static ISentinelSecurityBuilder AddSocialFederation(this ISentinelSecurityBuilder builder,
        Action<SocialFederationBuilder> configure)
    {
        var federationBuilder = new SocialFederationBuilder();
        configure(federationBuilder);

        _ = builder.Services.Configure<SocialFederationOptions>(options =>
        {
            options.FirstBrokerLoginFlowAlias = federationBuilder.Options.FirstBrokerLoginFlowAlias;
            options.Google = federationBuilder.Options.Google;
            options.GitHub = federationBuilder.Options.GitHub;
        });

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, SocialFederationConfiguratorHostedService>());
        return builder;
    }
}
