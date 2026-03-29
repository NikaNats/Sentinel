using System.Text.Json.Serialization;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application;

/// <summary>
///     JSON serialization context for Sentinel.Application business logic models.
///     Supports source-generated JSON serialization for Native AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TokenExchangeResult))]
[JsonSerializable(typeof(Dictionary<string, object>))]
public sealed partial class ApplicationJsonContext : JsonSerializerContext
{
}
