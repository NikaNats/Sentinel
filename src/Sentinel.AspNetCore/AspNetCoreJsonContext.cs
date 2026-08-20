using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth.Models;
using Sentinel.AspNetCore.Endpoints;

namespace Sentinel.AspNetCore;

/// <summary>
///     JSON serialization context for Sentinel.AspNetCore endpoint DTOs.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AuthEndpoints.RefreshRequest))]
[JsonSerializable(typeof(AuthEndpoints.RevokeRequest))]
[JsonSerializable(typeof(AuthEndpoints.ChangePasswordRequest))]
[JsonSerializable(typeof(AuthEndpoints.TotpSetupRequest))]
[JsonSerializable(typeof(AuthEndpoints.TotpVerifyRequest))]
[JsonSerializable(typeof(AuthEndpoints.TokenResponseDto))]
[JsonSerializable(typeof(TokenExchangeEndpoints.TokenExchangeResponseDto))]
[JsonSerializable(typeof(TokenExchangeEndpoints.TokenExchangeRequest))]
[JsonSerializable(typeof(UserSessionInfo))]
[JsonSerializable(typeof(IReadOnlyCollection<UserSessionInfo>))]
[JsonSerializable(typeof(List<UserSessionInfo>))]
[JsonSerializable(typeof(UserSessionInfo[]))]
[JsonSerializable(typeof(ProblemDetails))]
[JsonSerializable(typeof(ValidationProblemDetails))]
internal sealed partial class AspNetCoreJsonContext : JsonSerializerContext
{
}
