using System.Security.Claims;
using System.Text.Json;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;

namespace Sentinel.Application.Auth.Rar;

public static class RarExtensions
{
    public static AuthorizationDetail[] GetAuthorizationDetails(this ClaimsPrincipal user)
    {
        var claim = user.FindFirst("authorization_details");
        if (string.IsNullOrWhiteSpace(claim?.Value))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(claim.Value, RarJsonContext.Default.AuthorizationDetailArray) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
