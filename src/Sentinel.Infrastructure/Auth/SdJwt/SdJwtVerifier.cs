using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Infrastructure.Auth.SdJwt;

public sealed class SdJwtVerifier(
    IOptions<KeycloakOptions> keycloakOptions,
    IOptions<SdJwtOptions> sdJwtOptions,
    IConfigurationManager<OpenIdConnectConfiguration> openIdConfigurationManager,
    ILogger<SdJwtVerifier> logger) : ISdJwtVerifier
{
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private readonly KeycloakOptions keycloak = keycloakOptions.Value;
    private readonly SdJwtOptions options = sdJwtOptions.Value;

    public async Task<SdJwtVerificationResult> VerifyPresentationAsync(
        string sdJwtPresentation,
        string expectedAudience,
        string? expectedNonce,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(sdJwtPresentation))
        {
            return SdJwtVerificationResult.Fail("SD-JWT presentation is required.");
        }

        var parts = sdJwtPresentation.Split('~');
        if (parts.Length < 2)
        {
            return SdJwtVerificationResult.Fail("Invalid SD-JWT presentation format.");
        }

        var issuerJwt = parts[0];
        var kbJwt = parts[^1];
        var disclosures = parts.Length > 2 ? parts[1..^1] : [];
        if (string.IsNullOrWhiteSpace(kbJwt))
        {
            return SdJwtVerificationResult.Fail("Key binding JWT is missing.");
        }

        var issuerValidation = await ValidateIssuerTokenAsync(issuerJwt, expectedAudience, ct);
        if (!issuerValidation.IsValid || issuerValidation.SecurityToken is not JsonWebToken issuerToken)
        {
            return SdJwtVerificationResult.Fail("Issuer SD-JWT validation failed.");
        }

        var keyBindingError = await ValidateKeyBindingAsync(kbJwt, issuerToken, issuerJwt, disclosures, expectedAudience, expectedNonce);
        if (keyBindingError is not null)
        {
            return SdJwtVerificationResult.Fail(keyBindingError);
        }

        return ReconstructClaims(issuerToken, disclosures);
    }

    private async Task<TokenValidationResult> ValidateIssuerTokenAsync(string issuerJwt, string expectedAudience, CancellationToken ct)
    {
        var authority = keycloak.Authority.TrimEnd('/');
        var config = await openIdConfigurationManager.GetConfigurationAsync(ct);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = authority,
            ValidateAudience = true,
            ValidAudience = expectedAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        return await TokenHandler.ValidateTokenAsync(issuerJwt, parameters);
    }

    private async Task<string?> ValidateKeyBindingAsync(
        string kbJwt,
        JsonWebToken issuerToken,
        string issuerJwt,
        string[] disclosures,
        string expectedAudience,
        string? expectedNonce)
    {
        if (!TokenHandler.CanReadToken(kbJwt))
        {
            return "Invalid key binding token format.";
        }

        var kbToken = TokenHandler.ReadJsonWebToken(kbJwt);
        if (!kbToken.TryGetHeaderValue<object>("jwk", out var jwkObj) || jwkObj is null)
        {
            return "Key binding token header missing jwk.";
        }

        var jwkJson = jwkObj.ToString();
        if (string.IsNullOrWhiteSpace(jwkJson))
        {
            return "Key binding token jwk is invalid.";
        }

        JsonWebKey holderKey;
        try
        {
            holderKey = JsonWebKey.Create(jwkJson);
        }
        catch (ArgumentException)
        {
            return "Key binding token jwk is malformed.";
        }

        var kbValidation = await TokenHandler.ValidateTokenAsync(kbJwt, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = holderKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        });
        if (!kbValidation.IsValid)
        {
            return "Key binding signature validation failed.";
        }

        if (!kbToken.Audiences.Contains(expectedAudience))
        {
            return "Key binding audience mismatch.";
        }

        if (options.RequireKeyBindingNonce
            && (string.IsNullOrWhiteSpace(expectedNonce)
                || !kbToken.TryGetPayloadValue<string>("nonce", out var nonce)
                || !string.Equals(expectedNonce, nonce, StringComparison.Ordinal)))
        {
            return "Key binding nonce is missing or invalid.";
        }

        if (!kbToken.TryGetPayloadValue<long>("iat", out var iat))
        {
            return "Key binding token missing iat.";
        }

        var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
        var age = DateTimeOffset.UtcNow - iatTime;
        if (age < TimeSpan.Zero || age > TimeSpan.FromSeconds(Math.Max(1, options.KeyBindingMaxAgeSeconds)))
        {
            return "Key binding token is stale.";
        }

        if (!kbToken.TryGetPayloadValue<string>("sd_hash", out var sdHash) || string.IsNullOrWhiteSpace(sdHash))
        {
            return "Key binding token missing sd_hash.";
        }

        var presentationNoKb = $"{issuerJwt}~{string.Join("~", disclosures)}";
        var presentationNoKbWithTilde = $"{presentationNoKb}~";
        var sdHashNoKb = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKb)));
        var sdHashNoKbWithTilde = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKbWithTilde)));
        if (!string.Equals(sdHash, sdHashNoKb, StringComparison.Ordinal)
            && !string.Equals(sdHash, sdHashNoKbWithTilde, StringComparison.Ordinal))
        {
            return "Key binding sd_hash mismatch.";
        }

        if (issuerToken.TryGetPayloadValue<JsonElement>("cnf", out var cnf)
            && cnf.ValueKind == JsonValueKind.Object
            && cnf.TryGetProperty("jkt", out var jkt)
            && !string.IsNullOrWhiteSpace(jkt.GetString()))
        {
            using var jwkDoc = JsonDocument.Parse(jwkJson);
            var holderThumbprint = DpopThumbprintHelper.ComputeJwkThumbprint(jwkDoc.RootElement);
            if (!string.Equals(holderThumbprint, jkt.GetString(), StringComparison.Ordinal))
            {
                return "Key binding cnf.jkt mismatch.";
            }
        }

        return null;
    }

    private SdJwtVerificationResult ReconstructClaims(JsonWebToken issuerToken, string[] disclosures)
    {
        var identity = new ClaimsIdentity("SD-JWT");

        foreach (var claim in issuerToken.Claims)
        {
            if (string.Equals(claim.Type, "_sd", StringComparison.Ordinal)
                || string.Equals(claim.Type, "_sd_alg", StringComparison.Ordinal)
                || string.Equals(claim.Type, "cnf", StringComparison.Ordinal))
            {
                continue;
            }

            identity.AddClaim(claim);
        }

        var hashAlg = issuerToken.TryGetPayloadValue<string>("_sd_alg", out var value) ? value : "sha-256";
        if (!string.Equals(hashAlg, "sha-256", StringComparison.OrdinalIgnoreCase))
        {
            return SdJwtVerificationResult.Fail($"Unsupported disclosure hash algorithm: {hashAlg}");
        }

        var allowedDigests = ExtractDigests(issuerToken);
        foreach (var disclosure in disclosures)
        {
            if (string.IsNullOrWhiteSpace(disclosure))
            {
                continue;
            }

            var digest = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
            if (!allowedDigests.Contains(digest))
            {
                logger.LogWarning("Disclosure digest not present in issuer SD-JWT. digest={Digest}", digest);
                continue;
            }

            var decoded = Base64UrlEncoder.DecodeBytes(disclosure);
            using var doc = JsonDocument.Parse(decoded);
            if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() != 3)
            {
                continue;
            }

            var claimName = doc.RootElement[1].GetString();
            if (string.IsNullOrWhiteSpace(claimName))
            {
                continue;
            }

            var claimValue = doc.RootElement[2].ToString();
            identity.AddClaim(new Claim(claimName, claimValue));
        }

        return SdJwtVerificationResult.Success(new ClaimsPrincipal(identity));
    }

    private static HashSet<string> ExtractDigests(JsonWebToken token)
    {
        var digests = new HashSet<string>(StringComparer.Ordinal);
        if (!token.TryGetPayloadValue<JsonElement>("_sd", out var sdArray) || sdArray.ValueKind != JsonValueKind.Array)
        {
            return digests;
        }

        foreach (var element in sdArray.EnumerateArray())
        {
            var digest = element.GetString();
            if (!string.IsNullOrWhiteSpace(digest))
            {
                digests.Add(digest);
            }
        }

        return digests;
    }
}
