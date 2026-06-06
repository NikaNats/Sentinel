using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Security.Abstractions.SSF;

namespace Sentinel.Sample.MinimalApi;

/// <summary>
///     Minimal stub implementation of ISsfTokenValidator for demonstration/testing.
/// </summary>
internal sealed class SampleSsfTokenValidator : ISsfTokenValidator
{
    private readonly TokenValidationParameters _parameters = new()
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(5)
    };

    public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        try
        {
            var handler = new JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(setToken, _parameters);
            if (result.IsValid)
            {
                var jwt = new JsonWebToken(setToken);
                long issuedAt = 0;
                var iatClaim = jwt.Claims.FirstOrDefault(c => c.Type == "iat");
                if (iatClaim != null && long.TryParse(iatClaim.Value, out var parsed))
                {
                    issuedAt = parsed;
                }

                var token = new SsfEventToken(
                    GetFirstClaimValue(jwt, "iss") ?? string.Empty,
                    issuedAt,
                    GetFirstClaimValue(jwt, "jti") ?? string.Empty,
                    jwt.Audiences.FirstOrDefault() ?? string.Empty,
                    GetFirstClaimValue(jwt, "sub"),
                    ParseEvents(jwt));
                return SsfValidationResult.Success(token);
            }

            return SsfValidationResult.Fail(result.Exception?.Message ?? "Invalid SET token");
        }
        catch (SecurityTokenException ex)
        {
            return SsfValidationResult.Fail(ex.Message);
        }
    }

    private static Dictionary<string, JsonElement> ParseEvents(JsonWebToken jwt)
    {
        var events = new Dictionary<string, JsonElement>();
        var eventsClaim = GetFirstClaimValue(jwt, "events");
        if (!string.IsNullOrWhiteSpace(eventsClaim))
        {
            try
            {
                using var doc = JsonDocument.Parse(eventsClaim);
                foreach (var property in doc.RootElement.EnumerateObject())
                {
                    events[property.Name] = property.Value.Clone();
                }
            }
            catch (JsonException)
            {
            }
        }

        return events;
    }

    private static string? GetFirstClaimValue(JsonWebToken jwt, string claimType)
    {
        return jwt.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
}
