using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.SSF;

namespace AdversarialTestHost;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TransferRequest))]
[JsonSerializable(typeof(TransferResponse))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(ProblemDetails))]
[JsonSerializable(typeof(RefreshRequest))]
[JsonSerializable(typeof(RefreshResponse))]
[JsonSerializable(typeof(ChangePasswordRequest))]
[JsonSerializable(typeof(RevokeRequest))]
[JsonSerializable(typeof(DocumentSummaryDto))]
[JsonSerializable(typeof(DocumentDetailDto))]
[JsonSerializable(typeof(CreateDocumentRequest))]
[JsonSerializable(typeof(SecurityContextDto))]
[JsonSerializable(typeof(SampleInfoResponse))]
[JsonSerializable(typeof(EndpointMap))]
[JsonSerializable(typeof(TotpSetupRequest))]
[JsonSerializable(typeof(TotpVerifyRequest))]
[JsonSerializable(typeof(TokenExchangeRequest))]
[JsonSerializable(typeof(TokenExchangeResponse))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(DocumentSummaryDto[]))]
[JsonSerializable(typeof(ShowcaseTestResponse))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class TestHostJsonContext : JsonSerializerContext
{
}

public sealed record ShowcaseTestResponse(string Subject, string AssuranceLevel);

public sealed record TransferRequest(
    string TransactionId,
    decimal Amount,
    string Currency,
    string DestinationAccount);

public sealed record TransferResponse(
    string Status,
    string TransactionId,
    string Message,
    DateTimeOffset ProcessedAtUtc);

public sealed record HealthResponse(string Status, DateTimeOffset Utc);

public sealed record RefreshRequest(string RefreshToken);

public sealed record RefreshResponse(
    [property: JsonPropertyName("access_token")]
    string AccessToken,
    [property: JsonPropertyName("refresh_token")]
    string RefreshToken);

public sealed record ChangePasswordRequest(string NewPassword);

public sealed record RevokeRequest(string RefreshToken);

public sealed record CreateDocumentRequest(string Title, string Content);

public sealed record DocumentSummaryDto(
    string Id,
    string Title,
    int EncryptedBytes,
    DateTimeOffset CreatedUtc);

public sealed record DocumentDetailDto(
    string Id,
    string Title,
    string ContentPreview,
    int EncryptedBytes,
    DateTimeOffset CreatedUtc);

public sealed record SecurityContextDto(
    string Subject,
    string Acr,
    string DpopJkt,
    int AuthorizationDetailsCount,
    string TraceId);

public sealed record SampleInfoResponse(string Service, string Docs, EndpointMap Endpoints);

public sealed record EndpointMap(
    string Health,
    string Security,
    string Documents,
    string Finance,
    string Showcase);

public sealed record TotpSetupRequest(string DeviceName);

public sealed record TotpVerifyRequest(string Code);

public sealed record TokenExchangeRequest(
    string ExternalToken,
    string ProviderName,
    string CodeVerifier);

public sealed record TokenExchangeResponse(
    [property: JsonPropertyName("access_token")]
    string AccessToken,
    [property: JsonPropertyName("refresh_token")]
    string? RefreshToken,
    [property: JsonPropertyName("token_type")]
    string TokenType,
    [property: JsonPropertyName("expires_in")]
    int ExpiresIn,
    [property: JsonPropertyName("scope")] string? Scope);

internal sealed class SampleSdJwtTokenValidator : ISdJwtTokenValidator
{
    public Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
        string issuerJwt,
        string expectedAudience,
        CancellationToken cancellationToken = default)
    {
        var token = new JsonWebToken(issuerJwt);
        return Task.FromResult(SdJwtIssuerTokenValidationResult.Success(token));
    }
}

internal sealed class SampleSsfTokenValidator : ISsfTokenValidator
{
    public Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        var jwt = new JsonWebToken(setToken);
        var token = new SsfEventToken(
            "https://localhost:8443/realms/sentinel",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Guid.NewGuid().ToString("N"),
            "sentinel-api",
            "user-1",
            new Dictionary<string, JsonElement>());
        return Task.FromResult(SsfValidationResult.Success(token));
    }
}

internal sealed class SampleAuthRevocationService : IAuthRevocationService
{
    public Task<IReadOnlyCollection<UserSessionInfo>> GetActiveSessionsAsync(string subjectId, CancellationToken ct)
        => Task.FromResult<IReadOnlyCollection<UserSessionInfo>>(Array.Empty<UserSessionInfo>());

    public Task<bool> RevokeSessionAsync(string subjectId, string sessionId, CancellationToken ct)
        => Task.FromResult(true);

    public Task<bool> RevokeCurrentSessionAsync(string refreshToken, CancellationToken ct)
        => Task.FromResult(true);

    public Task<bool> RevokeAllSessionsAsync(string subjectId, CancellationToken ct)
        => Task.FromResult(true);

    public Task<bool> DeleteAccountAsync(string subjectId, CancellationToken ct)
        => Task.FromResult(true);
}
