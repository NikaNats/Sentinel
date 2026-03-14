using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Sentinel.Infrastructure.Auth;

public interface ILogoutTokenValidator
{
    Task<string?> ValidateAndExtractSessionIdAsync(string logoutToken, CancellationToken ct);
}

public sealed class LogoutTokenValidator(
    IOptionsMonitor<JwtBearerOptions> jwtOptionsMonitor,
    ILogger<LogoutTokenValidator> logger) : ILogoutTokenValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task<string?> ValidateAndExtractSessionIdAsync(string logoutToken, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(logoutToken))
        {
            return null;
        }

        var jwtOptions = jwtOptionsMonitor.Get(JwtBearerDefaults.AuthenticationScheme);
        var validationParameters = jwtOptions.TokenValidationParameters.Clone();
        validationParameters.ValidateLifetime = true;
        validationParameters.ClockSkew = TimeSpan.Zero;

        var validationResult = await TokenHandler.ValidateTokenAsync(logoutToken, validationParameters);
        if (!validationResult.IsValid || validationResult.SecurityToken is not JsonWebToken jwt)
        {
            logger.LogWarning("Back-channel logout token validation failed.");
            return null;
        }

        if (jwt.TryGetPayloadValue("nonce", out string? _))
        {
            logger.LogWarning("Back-channel logout token contains forbidden nonce claim.");
            return null;
        }

        if (!jwt.TryGetPayloadValue("events", out JsonElement events)
            || !events.TryGetProperty("http://schemas.openid.net/event/backchannel-logout", out _))
        {
            logger.LogWarning("Back-channel logout token missing required events claim.");
            return null;
        }

        return jwt.TryGetPayloadValue("sid", out string? sid) && !string.IsNullOrWhiteSpace(sid)
            ? sid
            : null;
    }
}
