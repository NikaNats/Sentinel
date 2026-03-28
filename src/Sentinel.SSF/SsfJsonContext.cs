using System.Text.Json.Serialization;

namespace Sentinel.SSF;

/// <summary>
///     JSON serialization context for RFC 8936 Security Event Framework types.
///     Supports source-generated JSON serialization for Native AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SessionRevokedPayload))]
[JsonSerializable(typeof(UserStatusChangedPayload))]
[JsonSerializable(typeof(CredentialChangePayload))]
[JsonSerializable(typeof(SsfEventToken))]
public sealed partial class SsfJsonContext : JsonSerializerContext
{
}
