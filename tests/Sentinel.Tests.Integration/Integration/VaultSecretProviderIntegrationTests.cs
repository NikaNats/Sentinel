using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Providers.Vault;
using Xunit;

namespace Sentinel.Tests.Integration.Integration;

public sealed class VaultSecretProviderIntegrationTests : IAsyncLifetime
{
    private const string RootToken = "sentinel-master-root-token";
    private const ushort VaultPort = 8200;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private readonly IContainer _vaultContainer = new ContainerBuilder("hashicorp/vault:1.15")
        .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", RootToken)
        .WithPortBinding(VaultPort, true)
        .WithWaitStrategy(Wait.ForUnixContainer()
            .UntilMessageIsLogged("Vault server started!"))
        .Build();

    private HttpClient? _httpClient;
    private VaultSecretProvider? _sut;
    private string _mockK8sJwt = string.Empty;
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

        _mockK8sJwt = MintMockKubernetesJwt(rsa);

        var options = new VaultOptions(_vaultAddress, "sentinel-api", _mockK8sJwt);
        _sut = new VaultSecretProvider(options, _httpClient, NullLogger<VaultSecretProvider>.Instance);

        await PrePopulateSecretAsync(_vaultAddress, TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        _sut?.Dispose();
        _httpClient?.Dispose();
        await _vaultContainer.DisposeAsync();
    }

    [Fact(DisplayName = "✅ Vault Integration: Successfully retrieves populated secret from real HashiCorp Vault container")]
    public async Task GetSecretAsync_FromRealVaultContainer_ReturnsCorrectSecret()
    {
        var secretValue = await _sut!.GetSecretAsync("sentinel/privacy", "MasterPepper", TestContext.Current.CancellationToken);

        secretValue.Should().Be("super-secret-pepper-bytes-2026");
    }

    private static async Task PrePopulateSecretAsync(string vaultAddress, CancellationToken cancellationToken)
    {
        using var setupClient = new HttpClient();
        setupClient.DefaultRequestHeaders.Add("X-Vault-Token", RootToken);

        var payload = new
        {
            data = new Dictionary<string, string>
            {
                ["MasterPepper"] = "super-secret-pepper-bytes-2026"
            }
        };

        using var response = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/secret/data/sentinel/privacy", payload, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static async Task ConfigureVaultJwtAuthAsKubernetesAsync(string vaultAddress, string publicKeyPem, CancellationToken cancellationToken)
    {
        using var setupClient = new HttpClient();
        setupClient.DefaultRequestHeaders.Add("X-Vault-Token", RootToken);

        var policyPayload = new
        {
            policy = "path \"secret/data/sentinel/privacy\" { capabilities = [\"read\"] }"
        };
        using var policyRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/sys/policies/acl/sentinel-read-policy", policyPayload, SerializerOptions, cancellationToken);
        policyRes.EnsureSuccessStatusCode();

        var authPayload = new { type = "jwt", description = "Mock Kubernetes Auth" };
        using var enableAuthRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/sys/auth/kubernetes", authPayload, SerializerOptions, cancellationToken);
        if (!enableAuthRes.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to enable auth backend: {await enableAuthRes.Content.ReadAsStringAsync(cancellationToken)}");
        }

        var configPayload = new
        {
            jwt_validation_pubkeys = new[] { publicKeyPem }
        };
        using var configRes = await setupClient.PostAsJsonAsync($"{vaultAddress}/v1/auth/kubernetes/config", configPayload, SerializerOptions, cancellationToken);
        if (!configRes.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to configure auth backend: {await configRes.Content.ReadAsStringAsync(cancellationToken)}");
        }

        var rolePayload = new
        {
            role_type = "jwt",
            user_claim = "sub",
            bound_subject = "system:serviceaccount:default:sentinel-api",
            policies = new[] { "default", "sentinel-read-policy" }
        };
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
