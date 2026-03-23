using System.Text.Json.Serialization;

namespace Sentinel.RAR;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AuthorizationDetail[]))]
public sealed partial class RarJsonContext : JsonSerializerContext
{
}
