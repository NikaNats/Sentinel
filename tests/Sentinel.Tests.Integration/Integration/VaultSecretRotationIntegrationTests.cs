using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Sentinel.Tests.Shared;
using System.Threading;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Providers.Vault;
using Xunit;

namespace Sentinel.Tests.Integration.Integration;

public sealed class VaultSecretRotationIntegrationTests : IAsyncLifetime
{
    private const string RootToken = "sentinel-master-root-token";
    private const ushort VaultPort = 8200;

    private static readonly JsonSerializerOptions SerializerOptions = TestJsonContext.Default.Options;

    private readonly IContainer _vaultContainer = new ContainerBuilder("hashicorp/vault:1.15")
        .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", RootToken)
        .WithPortBinding(VaultPort, true)
        .WithWaitStrategy(Wait.ForUnixContainer()
            .UntilMessageIsLogged("Vault server started!"))
        .Build();

    private HttpClient? _httpClient;
    private VaultSecretProvider? _secretProvider;
    private string _vaultAddress = string.Empty;

    public async ValueTask InitializeAsync()
    {
        await _vaultContainer.StartAsync(TestContext.Current.CancellationToken);

        var host = _vaultContainer.Hostname;
        var port = _vaultContainer.GetMappedPublicPort(VaultPort);
        _vaultAddress = $"http://{host}:{port}";

        _httpClient = new HttpClient { BaseAddress = new Uri(_vaultAddress) };

        using var rsa = RSA.Create(2048);
        var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem().Replace("\r\n", "\n", StringComparison.Ordinal);

        await ConfigureVaultJwtAuthAsKubernetesAsync(_vaultAddress, publicKeyPem, TestContext.Current.CancellationToken);

        var mockK8sJwt = MintMockKubernetesJwt(rsa);
        var options = new VaultOptions(_vaultAddress, "sentinel-api", mockK8sJwt);

        _secretProvider = new VaultSecretProvider(options, _httpClient, NullLogger<VaultSecretProvider>.Instance);
    }

    public async ValueTask DisposeAsync()
    {
        _secretProvider?.Dispose();
        _httpClient?.Dispose();
        await _vaultContainer.DisposeAsync();
    }

    [Fact(DisplayName = "?? Vault Zero-Downtime: Live pepper rotation in Vault seamlessly updates PrivacyKeyManager with fail-safe fallback")]
    public async Task RefreshKeyAsync_WhenSecretRotatesInVault_UpdatesPepperWithoutDowntime_AndFailsSafeOnOutage()
    {
        // 1. Prepare the initial MasterPepper V1 (32 bytes)
        var pepperV1Bytes = RandomNumberGenerator.GetBytes(32);
        var pepperV1Base64 = Convert.ToBase64String(pepperV1Bytes);
        await WriteSecretToVaultAsync("sentinel/privacy", "MasterPepper", pepperV1Base64);

        // ?? CA2000 fix: Added 'using' for automatic disposal
        using var keyManager = new PrivacyKeyManager(_secretProvider!, NullLogger<PrivacyKeyManager>.Instance);

        using var cts = new CancellationTokenSource();

        // 2. Start KeyManager (loads V1)
        await keyManager.StartAsync(cts.Token);

        // Verify that V1 was loaded successfully
        keyManager.GetMasterPepper().ToArray().Should().BeEquivalentTo(pepperV1Bytes,
            "Initial startup must fetch and set Pepper V1 from Vault.");

        // 3. Rotate the key in Vault -> MasterPepper V2 (32 bytes)
        var pepperV2Bytes = RandomNumberGenerator.GetBytes(32);
        var pepperV2Base64 = Convert.ToBase64String(pepperV2Bytes);
        await WriteSecretToVaultAsync("sentinel/privacy", "MasterPepper", pepperV2Base64);

        // Run the background refresh cycle (RefreshKeyAsync)
        var refreshMethod = typeof(PrivacyKeyManager)
            .GetMethod("RefreshKeyAsync", BindingFlags.NonPublic | BindingFlags.Instance);

        await (Task)refreshMethod!.Invoke(keyManager, new object[] { cts.Token })!;

        // Verify that the application switched to key V2 seamlessly (Zero-Downtime)
        keyManager.GetMasterPepper().ToArray().Should().BeEquivalentTo(pepperV2Bytes,
            "Live rotation in Vault must update active Master Pepper with Zero-Downtime.");

        // 4. Simulate Vault outage/failure (empty secret)
        await WriteSecretToVaultAsync("sentinel/privacy", "MasterPepper", "");

        // Run the refresh cycle under failure conditions
        await (Task)refreshMethod!.Invoke(keyManager, new object[] { cts.Token })!;

        // Fail-Safe check: During failure, the old V2 key must remain active and not shut down the system
        keyManager.GetMasterPepper().ToArray().Should().BeEquivalentTo(pepperV2Bytes,
            "During Vault outage or invalid secret update, old Master Pepper must remain active (Fail-Safe).");

        await keyManager.StopAsync(cts.Token);
    }

    private async Task WriteSecretToVaultAsync(string path, string key, string value)
    {
        using var setupClient = new HttpClient();
        setupClient.DefaultRequestHeaders.Add("X-Vault-Token", RootToken);

        var payload = new VaultSecretDataPayload(new Dictionary<string, string>
        {
            [key] = value
        });

        using var response = await setupClient.PostAsJsonAsync($"{_vaultAddress}/v1/secret/data/{path}", payload, TestJsonContext.Default.Options, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static async Task ConfigureVaultJwtAuthAsKubernetesAsync(string vaultAddress, string publicKeyPem, CancellationToken cancellationToken)
    {
        using var setupClient = new HttpClient();
        setupClient.DefaultRequestHeaders.Add("X-Vault-Token", RootToken);

        var policyPayload = new VaultPolicyPayload("path \"secret/data/sentinel/privacy\" { capabilities = [\"read\"] }");
        using var policyRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/sys/policies/acl/sentinel-read-policy", policyPayload, SerializerOptions, cancellationToken);
        policyRes.EnsureSuccessStatusCode();

        var authPayload = new VaultAuthPayload("jwt", "Mock Kubernetes Auth");
        using var enableAuthRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/sys/auth/kubernetes", authPayload, SerializerOptions, cancellationToken);
        if (!enableAuthRes.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to enable auth backend: {await enableAuthRes.Content.ReadAsStringAsync(cancellationToken)}");
        }

        var configPayload = new VaultConfigPayload([publicKeyPem]);
        using var configRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/auth/kubernetes/config", configPayload, SerializerOptions, cancellationToken);
        if (!configRes.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to configure auth backend: {await configRes.Content.ReadAsStringAsync(cancellationToken)}");
        }

        var rolePayload = new VaultRolePayload(
            "jwt",
            "sub",
            "system:serviceaccount:default:sentinel-api",
            ["default", "sentinel-read-policy"]);
        using var roleRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/auth/kubernetes/role/sentinel-api", rolePayload, SerializerOptions, cancellationToken);
        if (!roleRes.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to create role: {await roleRes.Content.ReadAsStringAsync(cancellationToken)}");
        }
    }

    private static string MintMockKubernetesJwt(RSA rsa)
    {
        var tokenHandler = new JsonWebTokenHandler();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "kubernetes/serviceaccount",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "system:serviceaccount:default:sentinel-api"
            },
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
        };

        return tokenHandler.CreateToken(descriptor);
    }
}
