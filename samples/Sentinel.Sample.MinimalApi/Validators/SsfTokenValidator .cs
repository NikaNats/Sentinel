using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Security.Abstractions.SSF;

namespace Sentinel.Sample.MinimalApi;

internal sealed class SsfTokenValidator : ISsfTokenValidator, IDisposable
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    private readonly ECDsa? _cachedEcdsa;
    private readonly ECDsaSecurityKey? _cachedKey;
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _configManager;
    private readonly IConfiguration _configuration;
    private readonly bool _isDevelopment;

    public SsfTokenValidator(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        IConfigurationManager<OpenIdConnectConfiguration>? configManager = null)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _isDevelopment = environment.IsDevelopment();
        _configManager = configManager;

        var testPublicKey = _configuration["Security:TestPublicKey"];
        if (!string.IsNullOrWhiteSpace(testPublicKey))
        {
            try
            {
                _cachedEcdsa = ECDsa.Create();
                _cachedEcdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(testPublicKey), out _);
                _cachedKey = new ECDsaSecurityKey(_cachedEcdsa) { KeyId = "test-authority-key" };
            }
            catch (Exception)
            {
                _cachedEcdsa?.Dispose();
                throw;
            }
        }
    }

    public void Dispose()
    {
        _cachedEcdsa?.Dispose();
    }

    public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(setToken) || !TokenHandler.CanReadToken(setToken))
        {
            return SsfValidationResult.Fail("SET token format is invalid.");
        }

        try
        {
            var keycloakSection = _configuration.GetSection("Keycloak");
            var authority = keycloakSection["Authority"] ?? string.Empty;
            var audience = keycloakSection["Audience"] ?? "sentinel-api";
            var allowedIssuers = new List<string> { authority };

            var testPublicKey = _configuration["Security:TestPublicKey"];
            if ((_isDevelopment || !string.IsNullOrWhiteSpace(testPublicKey)) &&
                !authority.Contains("localhost:8443", StringComparison.OrdinalIgnoreCase))
            {
                allowedIssuers.Add("https://localhost:8443/realms/sentinel");
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = allowedIssuers,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(5),
                RequireSignedTokens = true,
                ValidAlgorithms = ["PS256", "ES256"]
            };

            if (_cachedKey != null)
            {
                validationParameters.IssuerSigningKey = _cachedKey;
            }
            else if (_configManager != null)
            {
                var oidcConfig = await _configManager.GetConfigurationAsync(cancellationToken);
                validationParameters.IssuerSigningKeys = oidcConfig.SigningKeys;
            }
            else
            {
                return SsfValidationResult.Fail("Configuration manager for token validation is unavailable.");
            }

            var validationResult = await TokenHandler.ValidateTokenAsync(setToken, validationParameters);
            if (!validationResult.IsValid)
            {
                return SsfValidationResult.Fail(validationResult.Exception?.Message ?? "Signature validation failed.");
            }

            var jwt = TokenHandler.ReadJsonWebToken(setToken);
            if (!jwt.TryGetPayloadValue<JsonElement>("events", out var eventsElement) ||
                eventsElement.ValueKind != JsonValueKind.Object)
            {
                return SsfValidationResult.Fail("SET token does not contain a valid events payload.");
            }

            var events = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var prop in eventsElement.EnumerateObject())
            {
                events[prop.Name] = prop.Value.Clone();
            }

            long issuedAt = 0;
            if (jwt.TryGetPayloadValue<long>("iat", out var parsedIat))
            {
                issuedAt = parsedIat;
            }

            var jti = jwt.Id ?? Guid.NewGuid().ToString("N");

            var token = new SsfEventToken(
                jwt.Issuer,
                issuedAt,
                jti,
                jwt.Audiences.FirstOrDefault() ?? audience,
                jwt.Subject,
                events);

            return SsfValidationResult.Success(token);
        }
        catch (Exception ex) when (ex is SecurityTokenException or JsonException or CryptographicException)
        {
            return SsfValidationResult.Fail($"Security validation failed: {ex.Message}");
        }
    }
}
