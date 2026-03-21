using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Infrastructure.Auth.Ssf;

public sealed class JwtSsfTokenValidator(
    IOptions<KeycloakOptions> keycloakOptions,
    IOptions<SsfOptions> ssfOptions,
    IConfigurationManager<OpenIdConnectConfiguration> openIdConfigurationManager,
    ILogger<JwtSsfTokenValidator> logger) : ISsfTokenValidator
{
    private readonly JsonWebTokenHandler jwtHandler = new();
    private readonly KeycloakOptions options = keycloakOptions.Value;
    private readonly SsfOptions ssf = ssfOptions.Value;

    public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(setToken))
        {
            return SsfValidationResult.Fail("SET is required.");
        }

        try
        {
            var authority = options.Authority.TrimEnd('/');
            if (string.IsNullOrWhiteSpace(authority))
            {
                return SsfValidationResult.Fail("Keycloak authority is missing.");
            }

            var openIdConfig = await openIdConfigurationManager.GetConfigurationAsync(ct);

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = authority,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = openIdConfig.SigningKeys,
                ValidateLifetime = false,
                RequireExpirationTime = false,
                ClockSkew = TimeSpan.Zero
            };

            var validationResult = await jwtHandler.ValidateTokenAsync(setToken, parameters);
            if (!validationResult.IsValid || validationResult.SecurityToken is not JsonWebToken jwt)
            {
                return SsfValidationResult.Fail("SET is not a valid JWT.");
            }

            var iss = jwt.Issuer;
            var jti = jwt.Id;
            var iatRaw = jwt.TryGetPayloadValue<long>("iat", out var iatValue)
                ? iatValue.ToString(CultureInfo.InvariantCulture)
                : null;
            var aud = jwt.Audiences.FirstOrDefault() ?? string.Empty;
            var sub = jwt.Subject;

            if (string.IsNullOrWhiteSpace(jti) || string.IsNullOrWhiteSpace(iatRaw))
            {
                return SsfValidationResult.Fail("SET missing required jti/iat.");
            }

            if (!long.TryParse(iatRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var iat))
            {
                return SsfValidationResult.Fail("SET iat is invalid.");
            }

            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
            var now = DateTimeOffset.UtcNow;
            if (issuedAt > now.AddSeconds(Math.Max(0, ssf.AllowedClockSkewSeconds)))
            {
                return SsfValidationResult.Fail("SET iat is in the future.");
            }

            if (now - issuedAt > TimeSpan.FromSeconds(Math.Max(1, ssf.MaxEventAgeSeconds)))
            {
                return SsfValidationResult.Fail("SET is too old.");
            }

            if (!jwt.TryGetPayloadValue<JsonElement>("events", out var eventsElement))
            {
                return SsfValidationResult.Fail("SET events claim is missing.");
            }

            var events = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(eventsElement.GetRawText());
            if (events is null || events.Count == 0)
            {
                return SsfValidationResult.Fail("SET events claim is empty.");
            }

            return SsfValidationResult.Success(new SecurityEventToken(iss, iat, jti, aud, sub, events));
        }
        catch (SecurityTokenException ex)
        {
            logger.LogWarning(ex, "SET validation failed due to token security validation.");
            return SsfValidationResult.Fail("SET signature or issuer validation failed.");
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "SET validation failed.");
            return SsfValidationResult.Fail("SET validation failed.");
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "SET validation failed.");
            return SsfValidationResult.Fail("SET validation failed.");
        }
        catch (JsonException ex)
        {
            logger.LogError(ex, "SET validation failed.");
            return SsfValidationResult.Fail("SET validation failed.");
        }
    }
}
