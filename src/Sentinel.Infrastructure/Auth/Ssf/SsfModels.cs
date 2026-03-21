using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Infrastructure.Auth.Ssf;

public sealed record SecurityEventToken(
    [property: JsonPropertyName("iss")] string Issuer,
    [property: JsonPropertyName("iat")] long IssuedAt,
    [property: JsonPropertyName("jti")] string Jti,
    [property: JsonPropertyName("aud")] string Audience,
    [property: JsonPropertyName("sub")] string? Subject,
    [property: JsonPropertyName("events")] Dictionary<string, JsonElement> Events);

public sealed record SessionRevokedPayload(
    [property: JsonPropertyName("sid")] string? SessionId,
    [property: JsonPropertyName("sub")] string? Subject);

public sealed record UserStatusChangedPayload(
    [property: JsonPropertyName("sub")] string? Subject);

public sealed record SsfValidationResult(bool IsValid, SecurityEventToken? Token, string? Error)
{
    public static SsfValidationResult Success(SecurityEventToken token) => new(true, token, null);

    public static SsfValidationResult Fail(string error) => new(false, null, error);
}
