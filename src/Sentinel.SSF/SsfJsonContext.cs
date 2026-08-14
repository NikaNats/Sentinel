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
[JsonSerializable(typeof(SsfSetPayload))]
public sealed partial class SsfJsonContext : JsonSerializerContext
{
}

/// <summary>RFC 8936 SET wrapper envelope: <c>{"set": "&lt;jwt&gt;"}</c>.</summary>
public sealed record SsfSetPayload(string Set);
