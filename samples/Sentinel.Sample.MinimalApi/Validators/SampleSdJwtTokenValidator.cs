using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.SdJwt;

namespace Sentinel.Sample.MinimalApi;

internal sealed class SampleSdJwtTokenValidator : ISdJwtTokenValidator, IDisposable
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    private readonly ECDsa? _cachedEcdsa;
    private readonly ECDsaSecurityKey? _cachedKey;

    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly SdJwtVerificationOptions _options;

    public SampleSdJwtTokenValidator(
        IConfiguration configuration,
        IOptions<SdJwtVerificationOptions> options,
        IWebHostEnvironment environment)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

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

    public async Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
        string issuerJwt,
        string expectedAudience,
        CancellationToken cancellationToken = default)
    {
        var keycloakSection = _configuration.GetSection("Keycloak");
        var authority = keycloakSection["Authority"] ?? string.Empty;
        var audience = keycloakSection["Audience"] ?? "sentinel-api";
        var allowedIssuers = new List<string> { authority };

        var testPublicKey = _configuration["Security:TestPublicKey"];
        if ((_environment.IsDevelopment() || !string.IsNullOrWhiteSpace(testPublicKey)) &&
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
            ClockSkew = TimeSpan.FromSeconds(_options.AllowedClockSkewSeconds),
            RequireSignedTokens = true,
            ValidAlgorithms = ["PS256", "ES256"]
        };

        if (_cachedKey != null)
        {
            validationParameters.IssuerSigningKey = _cachedKey;
            validationParameters.IssuerSigningKeys = [_cachedKey];
        }

        try
        {
            var result = await TokenHandler.ValidateTokenAsync(issuerJwt, validationParameters);
            if (result.IsValid)
            {
                var token = new JsonWebToken(issuerJwt);
                return SdJwtIssuerTokenValidationResult.Success(token);
            }

            return SdJwtIssuerTokenValidationResult.Failure(result.Exception?.Message ??
                                                            "Invalid SD-JWT issuer token.");
        }
        catch (SecurityTokenException ex)
        {
            return SdJwtIssuerTokenValidationResult.Failure(ex.Message);
        }
        catch (CryptographicException ex)
        {
            return SdJwtIssuerTokenValidationResult.Failure($"Cryptographic failure: {ex.Message}");
        }
    }
}
