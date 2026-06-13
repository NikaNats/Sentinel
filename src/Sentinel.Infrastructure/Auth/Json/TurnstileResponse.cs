using System.Text.Json.Serialization;

namespace Sentinel.Infrastructure.Auth.Json;

public sealed record TurnstileResponse(
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("error-codes")] string[]? ErrorCodes,
    [property: JsonPropertyName("challenge_ts")] string? ChallengeTs,
    [property: JsonPropertyName("hostname")] string? Hostname
);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TurnstileResponse))]
internal sealed partial class CaptchaJsonContext : JsonSerializerContext
{
}
