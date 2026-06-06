using System.Text.Json.Serialization;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.Redis;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CachedHttpResponse))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class RedisJsonContext : JsonSerializerContext
{
}
