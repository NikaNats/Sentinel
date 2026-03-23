namespace Sentinel.SdJwt;

using System.Text.Json.Serialization;

/// <summary>
/// JSON serialization context for RFC 9901 Selective Disclosure for JWTs types.
/// Supports source-generated JSON serialization for Native AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, object[]>))]
public sealed partial class SdJwtJsonContext : JsonSerializerContext { }
