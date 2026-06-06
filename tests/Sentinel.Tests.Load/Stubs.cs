using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.SSF;

namespace AdversarialTestHost;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TransferRequest))]
[JsonSerializable(typeof(TransferResponse))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(ProblemDetails))]
internal sealed partial class TestHostJsonContext : JsonSerializerContext
{
}

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
    public Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}
