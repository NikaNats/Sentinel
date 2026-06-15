using System.Text.Json.Serialization;
using Sentinel.Domain.Auth.Rar;

namespace Sentinel.RAR;

/// <summary>
///     JSON serialization context for RAR types (RFC 9396).
///     Supports source-generated JSON serialization for Native AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AuthorizationDetail[]))]
[JsonSerializable(typeof(AuthorizationDetail))]
public sealed partial class RarJsonContext : JsonSerializerContext
{
}
