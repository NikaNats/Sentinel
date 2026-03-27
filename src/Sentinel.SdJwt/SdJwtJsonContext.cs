namespace Sentinel.SdJwt;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// JSON serialization context for RFC 9901 Selective Disclosure for JWTs types.
/// Supports source-generated JSON serialization for Native AOT compatibility.
/// Uses JsonElement for AOT-safe complex type handling instead of object.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
[JsonSerializable(typeof(Dictionary<string, JsonElement[]>))]
public sealed partial class SdJwtJsonContext : JsonSerializerContext { }
