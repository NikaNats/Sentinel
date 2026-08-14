using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.SSF;

namespace Sentinel.Tests.SSF.Helpers;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SidPayload))]
[JsonSerializable(typeof(SubPayload))]
[JsonSerializable(typeof(int))]
public sealed partial class SsfTestPayloadsJsonContext : JsonSerializerContext
{
}

public sealed record SidPayload(string Sid);

public sealed record SubPayload(string Sub);

/// <summary>
///     High-assurance mock ISsfTokenValidator for security-focused testing.
///     Supports injection of realistic, IANA-registered CAEP event payloads for adversarial testing.
/// </summary>
public sealed class MockSsfTokenValidator : ISsfTokenValidator
{
    /// <summary>
    ///     Custom result to return from ValidateAsync (if set, overrides default behavior).
    /// </summary>
    public SsfValidationResult? CustomResult { get; set; }

    public Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        if (CustomResult != null)
        {
            return Task.FromResult(CustomResult);
        }

        // Default successful but empty token (no security events)
        var token = new SsfEventToken(
            "https://idp.sentinel.io",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            $"evt-{Guid.NewGuid():N}",
            "sentinel-api",
            "user-1",
            new Dictionary<string, JsonElement>());

        return Task.FromResult(SsfValidationResult.Success(token));
    }

    /// <summary>
    ///     Helper to create properly serialized CAEP event payloads for SET token testing.
    /// </summary>
    /// <remarks>
    ///     CAEP (Continuous Access Evaluation Profile) defines a standard set of event URIs
    ///     and payload structures. This helper ensures test payloads conform to the spec.
    ///     See: https://tools.ietf.org/html/draft-ietf-caep-core
    /// </remarks>
    public static JsonElement CreateCaepPayload(object payload)
        => JsonSerializer.SerializeToElement(payload, SsfTestPayloadsJsonContext.Default.Options);
}
