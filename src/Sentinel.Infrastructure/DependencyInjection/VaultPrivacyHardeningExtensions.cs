using Microsoft.Extensions.DependencyInjection;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Providers.Vault;
using Sentinel.Security.Abstractions.DependencyInjection;
using Sentinel.Security.Abstractions.Pqc;
using Sentinel.Security.Abstractions.Secrets;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class VaultPrivacyHardeningExtensions
{
    public static ISentinelSecurityBuilder AddVaultPrivacyHardening(this ISentinelSecurityBuilder builder,
        IConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(config);

        var vaultOptions = new VaultOptions(
            config["Vault:Address"] ?? "https://vault.internal:8200",
            config["Vault:RoleName"] ?? "sentinel-api",
            config["Vault:FallbackToken"] ?? ""
        );

        builder.Services.AddSingleton(vaultOptions);

        builder.Services.AddHttpClient<ISecretProvider, VaultSecretProvider>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(5);
        });

        builder.Services.AddSingleton<IMlDsaSignatureVerifier, NotSupportedMlDsaVerifier>();

        builder.Services.AddSingleton<PrivacyKeyManager>();
        builder.Services.AddSingleton<IPrivacyKeyManager>(sp => sp.GetRequiredService<PrivacyKeyManager>());
        builder.Services.AddHostedService(sp => sp.GetRequiredService<PrivacyKeyManager>());

        builder.Services.AddSingleton<IPrivacyPreservingHasher, PrivacyPreservingHasher>();

        return builder;
    }
}
