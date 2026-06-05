using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Providers.Vault;
using Sentinel.Security.Abstractions.DependencyInjection;
using Sentinel.Security.Abstractions.Secrets;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Infrastructure.DependencyInjection;

public static class VaultPrivacyHardeningExtensions
{
    public static ISentinelSecurityBuilder AddVaultPrivacyHardening(this ISentinelSecurityBuilder builder, IConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(config);

        var vaultOptions = new VaultOptions(
            VaultAddress: config["Vault:Address"] ?? "https://vault.internal:8200",
            RoleName: config["Vault:RoleName"] ?? "sentinel-api",
            FallbackToken: config["Vault:FallbackToken"] ?? ""
        );

        builder.Services.AddSingleton(vaultOptions);

        // 🟢 HttpClient კავშირების პულინგით და ოპტიმალური თაიმაუტებით
        builder.Services.AddHttpClient<ISecretProvider, VaultSecretProvider>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(5);
        });

        // Key Manager (Background Worker)
        builder.Services.AddSingleton<PrivacyKeyManager>();
        builder.Services.AddSingleton<IPrivacyKeyManager>(sp => sp.GetRequiredService<PrivacyKeyManager>());
        builder.Services.AddHostedService(sp => sp.GetRequiredService<PrivacyKeyManager>());

        // Cryptographic Hasher
        builder.Services.AddSingleton<IPrivacyPreservingHasher, PrivacyPreservingHasher>();

        return builder;
    }
}
