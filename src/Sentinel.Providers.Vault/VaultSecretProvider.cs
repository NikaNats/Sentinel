using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sentinel.Security.Abstractions.Secrets;

namespace Sentinel.Providers.Vault;

// 🟢 JSON Source Generation ოპტიმიზაცია Native AOT-სთვის
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(VaultLoginRequest))]
[JsonSerializable(typeof(VaultLoginResponse))]
[JsonSerializable(typeof(VaultSecretResponse))]
internal sealed partial class VaultJsonContext : JsonSerializerContext { }

internal sealed record VaultLoginRequest(string Role, string Jwt);
internal sealed record VaultLoginResponse(VaultAuthData Auth);
internal sealed record VaultAuthData(string ClientToken);
internal sealed record VaultSecretResponse(VaultSecretData Data);
internal sealed record VaultSecretData(Dictionary<string, string> Data);

public sealed class VaultSecretProvider : ISecretProvider, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly VaultOptions _options;
    private readonly ILogger<VaultSecretProvider> _logger;
    private string? _vaultToken;
    private DateTimeOffset _tokenExpiry = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _authLock = new(1, 1);

    public VaultSecretProvider(VaultOptions options, HttpClient httpClient, ILogger<VaultSecretProvider> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _httpClient.BaseAddress = new Uri(options.VaultAddress.TrimEnd('/'));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async ValueTask<string?> GetSecretAsync(string secretPath, string key, CancellationToken cancellationToken = default)
    {
        await EnsureAuthenticatedAsync(cancellationToken).ConfigureAwait(false);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"/v1/secret/data/{secretPath}");
        request.Headers.Add("X-Vault-Token", _vaultToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            _vaultToken = null; // ძალდატანებითი რე-ავტორიზაცია შემდეგ ცდაზე
            throw new UnauthorizedAccessException("Vault Token expired or revoked.");
        }

        response.EnsureSuccessStatusCode();

        // 🟢 სუფთა დესერიალიზაცია რეფლექსიის გარეშე (AOT-სთვის)
        var secretData = await response.Content.ReadFromJsonAsync(
            VaultJsonContext.Default.VaultSecretResponse, cancellationToken).ConfigureAwait(false);

        if (secretData?.Data?.Data != null && secretData.Data.Data.TryGetValue(key, out var value))
        {
            return value;
        }

        return null;
    }

    private async Task EnsureAuthenticatedAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_vaultToken) && DateTimeOffset.UtcNow < _tokenExpiry) return;

        await _authLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrEmpty(_vaultToken) && DateTimeOffset.UtcNow < _tokenExpiry) return;

            // 🟢 ტოკენის დინამიური წაკითხვა დისკიდან ყოველ ჯერზე (როტაციის დაზღვევა!)
            var k8sJwtPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
            var jwt = File.Exists(k8sJwtPath)
                ? await File.ReadAllTextAsync(k8sJwtPath, cancellationToken).ConfigureAwait(false)
                : _options.FallbackToken;

            if (string.IsNullOrWhiteSpace(jwt))
                throw new InvalidOperationException("K8s ServiceAccount JWT is missing and fallback token is empty.");

            var loginReq = new VaultLoginRequest(_options.RoleName, jwt);

            using var response = await _httpClient.PostAsJsonAsync(
                "/v1/auth/kubernetes/login",
                loginReq,
                VaultJsonContext.Default.VaultLoginRequest,
                cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            var loginRes = await response.Content.ReadFromJsonAsync(
                VaultJsonContext.Default.VaultLoginResponse, cancellationToken).ConfigureAwait(false);

            _vaultToken = loginRes?.Auth?.ClientToken ?? throw new InvalidOperationException("Vault Login response is empty.");
            _tokenExpiry = DateTimeOffset.UtcNow.AddMinutes(50); // ვანახლებთ კავშირს 50 წუთში ერთხელ

            _logger.LogInformation("Successfully authenticated to HashiCorp Vault using K8s Workload Identity.");
        }
        finally
        {
            _authLock.Release();
        }
    }

    public void Dispose() => _authLock.Dispose();
}

public sealed record VaultOptions(string VaultAddress, string RoleName, string FallbackToken = "");
