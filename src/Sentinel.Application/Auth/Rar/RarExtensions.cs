using System.Security.Claims;
using System.Text.Json;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;

namespace Sentinel.Application.Auth.Rar;

public static class RarExtensions
{
    public static AuthorizationDetail[] GetAuthorizationDetails(this ClaimsPrincipal user)
    {
        var claims = user.FindAll("authorization_details").ToList();
        if (claims.Count == 0)
        {
            return [];
        }

        var details = new List<AuthorizationDetail>();

        foreach (var claim in claims)
        {
            var val = claim.Value.Trim();
            if (string.IsNullOrWhiteSpace(val))
            {
                continue;
            }

            try
            {
                var firstChar = val[0];
                var lastChar = val[^1];

                switch (firstChar)
                {
                    case '[' when lastChar == ']':
                    {
                        var array = JsonSerializer.Deserialize(val, RarJsonContext.Default.AuthorizationDetailArray);
                        if (array != null)
                        {
                            details.AddRange(array);
                        }

                        break;
                    }
                    case '{' when lastChar == '}':
                    {
                        var singleDetail = JsonSerializer.Deserialize(val, RarJsonContext.Default.AuthorizationDetail);
                        if (singleDetail != null)
                        {
                            details.Add(singleDetail);
                        }

                        break;
                    }
                }
            }
            catch (JsonException)
            {
            }
        }

        return details.ToArray();
    }
}
