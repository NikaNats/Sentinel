using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Security.Abstractions.SSF;

namespace Sentinel.AspNetCore.Ssf;

public static class SentinelSsfReceiverExtensions
{
    /// <summary>
    ///     Registers a JWKS-backed <see cref="ISsfTokenValidator" /> for Security Event Tokens signed by
    ///     <paramref name="issuer" />. Signing keys come from the issuer's OIDC discovery document over HTTPS.
    ///     Pair with <c>AddSsfProcessing</c> and <c>AddSentinelHostBridges</c>, and set <c>Ssf:Enabled</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="issuer">The SET issuer; must equal the token's <c>iss</c> and host the discovery document.</param>
    /// <param name="audience">The expected <c>aud</c> of incoming SETs.</param>
    /// <param name="backchannel">Optional hardened handler for discovery/JWKS calls (e.g. TLS 1.3 + custom CA).</param>
    public static IServiceCollection AddSentinelSsfTokenValidation(
        this IServiceCollection services,
        string issuer,
        string audience,
        HttpMessageHandler? backchannel = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        var normalizedIssuer = issuer.TrimEnd('/');
        services.TryAddSingleton<ISsfTokenValidator>(sp =>
        {
            var httpClient = backchannel is null
                ? new HttpClient { Timeout = TimeSpan.FromSeconds(15) }
                : new HttpClient(backchannel, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(15) };
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{normalizedIssuer}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(httpClient) { RequireHttps = true });

            return new JwksSsfTokenValidator(
                normalizedIssuer,
                audience,
                configurationManager,
                sp.GetRequiredService<ILogger<JwksSsfTokenValidator>>());
        });

        return services;
    }
}

/// <summary>
///     Validates a Security Event Token (RFC 8417): signature against the issuer's JWKS, exact issuer and
///     audience, PS256/ES256 only, and an <c>events</c> object. Failure details are logged, never returned.
/// </summary>
internal sealed class JwksSsfTokenValidator(
    string issuer,
    string audience,
    IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
    ILogger<JwksSsfTokenValidator> logger) : ISsfTokenValidator
{
    private const string GenericFailure = "SET signature or claims validation failed.";
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private static readonly string[] AllowedAlgorithms = ["PS256", "ES256"];

    public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(setToken) || !TokenHandler.CanReadToken(setToken))
        {
            return SsfValidationResult.Fail("SET token format is invalid.");
        }

        try
        {
            var oidcConfig = await configurationManager.GetConfigurationAsync(cancellationToken);
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                // RFC 8417: a SET need not carry exp; freshness is bounded by the processor's iat age check.
                ValidateLifetime = false,
                RequireExpirationTime = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = oidcConfig.SigningKeys,
                ValidAlgorithms = AllowedAlgorithms
            };

            var result = await TokenHandler.ValidateTokenAsync(setToken, parameters);
            if (!result.IsValid)
            {
                if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                {
                    configurationManager.RequestRefresh();
                }

                logger.LogWarning(result.Exception, "SET validation failed.");
                return SsfValidationResult.Fail(GenericFailure);
            }

            var jwt = (JsonWebToken)result.SecurityToken;
            if (!jwt.TryGetPayloadValue<JsonElement>("events", out var eventsElement)
                || eventsElement.ValueKind != JsonValueKind.Object)
            {
                return SsfValidationResult.Fail("SET token does not contain a valid events payload.");
            }

            if (!jwt.TryGetPayloadValue<long>("iat", out var issuedAt))
            {
                return SsfValidationResult.Fail("SET token is missing iat.");
            }

            var events = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in eventsElement.EnumerateObject())
            {
                events[property.Name] = property.Value.Clone();
            }

            return SsfValidationResult.Success(new SsfEventToken(
                jwt.Issuer,
                issuedAt,
                jwt.Id ?? string.Empty,
                audience,
                jwt.Subject,
                events));
        }
        catch (Exception ex) when (ex is SecurityTokenException or JsonException or CryptographicException
                                       or InvalidOperationException or HttpRequestException)
        {
            logger.LogWarning(ex, "SET validation failed.");
            return SsfValidationResult.Fail(GenericFailure);
        }
    }
}
