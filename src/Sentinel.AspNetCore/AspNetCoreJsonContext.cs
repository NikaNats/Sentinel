using System.Text.Json.Serialization;
using Sentinel.AspNetCore.Endpoints;

namespace Sentinel.AspNetCore;

/// <summary>
/// JSON serialization context for Sentinel.AspNetCore endpoint DTOs.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AuthEndpoints.RefreshRequest))]
[JsonSerializable(typeof(AuthEndpoints.RevokeRequest))]
[JsonSerializable(typeof(AuthEndpoints.ChangePasswordRequest))]
[JsonSerializable(typeof(AuthEndpoints.TotpSetupRequest))]
[JsonSerializable(typeof(AuthEndpoints.TotpVerifyRequest))]
[JsonSerializable(typeof(TokenExchangeEndpoints.TokenExchangeRequest))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ValidationProblemDetails))]
internal sealed partial class AspNetCoreJsonContext : JsonSerializerContext
{
}
