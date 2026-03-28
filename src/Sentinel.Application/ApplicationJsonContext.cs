namespace Sentinel.Application;

using System.Text.Json.Serialization;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Auth.Rar;

/// <summary>
/// JSON serialization context for Sentinel.Application business logic models.
/// Supports source-generated JSON serialization for Native AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TokenExchangeResult))]
[JsonSerializable(typeof(AuthorizationDetail))]
[JsonSerializable(typeof(AuthorizationDetail[]))]
[JsonSerializable(typeof(Dictionary<string, object>))]
public sealed partial class ApplicationJsonContext : JsonSerializerContext { }
