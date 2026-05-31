using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Application.Auth.Models;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.SSF;
using ApplicationAuthRevocationService = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;
using ApplicationSsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;
using SecuritySsfEventProcessor = Sentinel.Security.Abstractions.SSF.ISsfEventProcessor;

namespace Sentinel.Tests.Shared.Fixtures;

public sealed class TestSdJwtTokenValidator : ISdJwtTokenValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
        string issuerJwt,
        string expectedAudience,
        CancellationToken cancellationToken = default)
    {
        if (!TokenHandler.CanReadToken(issuerJwt))
        {
            return SdJwtIssuerTokenValidationResult.Failure("Issuer token is not a readable JWT.");
        }

        var validation = await TokenHandler.ValidateTokenAsync(issuerJwt, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey,
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:8443/realms/sentinel",
            ValidateAudience = true,
            ValidAudience = expectedAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(5)
        });

        if (!validation.IsValid)
        {
            return SdJwtIssuerTokenValidationResult.Failure("Issuer token validation failed.");
        }

        return SdJwtIssuerTokenValidationResult.Success(TokenHandler.ReadJsonWebToken(issuerJwt));
    }
}

public sealed class TestSsfTokenValidator : ISsfTokenValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(setToken) || !TokenHandler.CanReadToken(setToken))
        {
            return SsfValidationResult.Fail("SET token format is invalid.");
        }

        var validation = await TokenHandler.ValidateTokenAsync(setToken, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey,
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:8443/realms/sentinel",
            ValidateAudience = true,
            ValidAudience = "sentinel-api",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(5)
        });

        if (!validation.IsValid)
        {
            return SsfValidationResult.Fail("SET signature or claims validation failed.");
        }

        var token = TokenHandler.ReadJsonWebToken(setToken);
        if (!token.TryGetPayloadValue<JsonElement>("events", out var eventsElement)
            || eventsElement.ValueKind != JsonValueKind.Object)
        {
            return SsfValidationResult.Fail("SET token does not contain valid events payload.");
        }

        var events = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in eventsElement.EnumerateObject())
        {
            events[property.Name] = property.Value;
        }

        var issuer = token.Issuer;
        var audience = token.Audiences.FirstOrDefault() ?? "sentinel-api";
        var subject = token.Subject;
        if (!token.TryGetPayloadValue<long>("iat", out var issuedAt))
        {
            issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        if (!token.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
        {
            jti = Guid.NewGuid().ToString("N");
        }

        return SsfValidationResult.Success(new SsfEventToken(issuer, issuedAt, jti, audience, subject, events));
    }
}

public sealed class AuthRevocationServiceAdapter(ApplicationAuthRevocationService inner) : IAuthRevocationService
{
    public async Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
    {
        _ = await inner.RevokeAllSessionsAsync(subject, cancellationToken);
    }
}

public sealed class SsfEventProcessorAdapter(SecuritySsfEventProcessor inner) : ApplicationSsfEventProcessor
{
    public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
    {
        var result = await inner.ProcessAsync(setToken, ct);
        if (result.IsSuccess)
        {
            return SsfProcessResult.Success();
        }

        throw new InvalidOperationException(result.ErrorMessage ?? "SSF processing failed.");
    }
}
