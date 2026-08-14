using System.Text.Json;
using System.Text.Json.Serialization;
using AdversarialTestHost;
using Sentinel.SSF;

namespace Sentinel.Tests.Acceptance.Steps;

/// <summary>
///     Source-generated JSON context for the acceptance suite. With
///     <c>JsonSerializerIsReflectionEnabledByDefault=false</c> the suite behaves
///     like Native AOT for System.Text.Json, so any payload serialized without an
///     explicit context fails fast instead of silently using the reflection fallback.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TransferRequest))]
[JsonSerializable(typeof(TransferResponse))]
[JsonSerializable(typeof(SsfSetPayload))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(JsonElement))]
public sealed partial class AcceptanceJsonContext : JsonSerializerContext
{
}
