using System.Text.Json.Serialization;

namespace Sentinel.DPoP;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Dictionary<string, string>))]
public sealed partial class DpopJsonContext : JsonSerializerContext
{
}
