using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Infrastructure.Auth;
using Sentinel.Security.Diagnostics;

namespace Sentinel.AspNetCore.Authentication;

/// <summary>
///     JwtBearer wiring that connects ASP.NET Core authentication to Sentinel's post-signature checks
///     (session blacklist, optional access-token jti single use) and DPoP-scheme token extraction.
/// </summary>
public static class SentinelJwtBearerExtensions
{
    private static readonly string[] AllowedAccessTokenAlgorithms = ["PS256", "ES256"];

    /// <summary>
    ///     Adds the JwtBearer scheme with Sentinel's strict defaults: exact issuer and audience, zero clock skew,
    ///     PS256/ES256 only, HTTPS metadata, no inbound claim mapping, and <see cref="SentinelJwtBearerEvents" />.
    ///     <paramref name="configure" /> runs last, so a host can override any default (e.g. the backchannel handler).
    /// </summary>
    public static AuthenticationBuilder AddSentinelJwtBearer(
        this AuthenticationBuilder builder,
        string authority,
        string audience,
        Action<JwtBearerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<TokenValidationService>();

        var issuer = authority.TrimEnd('/');
        return builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            options.MapInboundClaims = false;
            options.Authority = issuer;
            options.Audience = audience;
            options.RequireHttpsMetadata = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuerSigningKey = true,
                ValidAlgorithms = AllowedAccessTokenAlgorithms
            };
            options.Events = SentinelJwtBearerEvents.Create();

            configure?.Invoke(options);
        });
    }
}

/// <summary>
///     Factory for the JwtBearer event handlers every Sentinel host needs.
/// </summary>
public static class SentinelJwtBearerEvents
{
    private const string DpopScheme = "DPoP ";
    private const string BearerScheme = "Bearer ";

    /// <summary>
    ///     Creates the handlers:
    ///     <list type="bullet">
    ///         <item>OnMessageReceived: accepts <c>Authorization: DPoP &lt;token&gt;</c> (proof checked by DpopValidationMiddleware).</item>
    ///         <item>OnTokenValidated: re-materializes exp/sid/sub/acr/scope and runs <see cref="TokenValidationService" />.</item>
    ///         <item>OnChallenge: RFC 9457 problem with a generic detail; exception text never reaches the client.</item>
    ///         <item>OnAuthenticationFailed: JWKS kid-miss telemetry.</item>
    ///     </list>
    /// </summary>
    public static JwtBearerEvents Create() => new()
    {
        OnMessageReceived = OnMessageReceived,
        OnTokenValidated = OnTokenValidatedAsync,
        OnChallenge = OnChallengeAsync,
        OnAuthenticationFailed = OnAuthenticationFailed
    };

    private static Task OnMessageReceived(MessageReceivedContext context)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith(DpopScheme, StringComparison.OrdinalIgnoreCase))
        {
            context.Token = authHeader[DpopScheme.Length..].Trim();
        }

        return Task.CompletedTask;
    }

    private static async Task OnTokenValidatedAsync(TokenValidatedContext context)
    {
        if (context.SecurityToken is not JsonWebToken jwt || context.Principal?.Identity is not ClaimsIdentity identity)
        {
            context.Fail(new SecurityTokenException("Unsupported security token."));
            return;
        }

        var exp = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value
                  ?? new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        AddClaimIfMissing(identity, "exp", exp);
        AddClaimIfMissing(identity, "sid", jwt.Claims.FirstOrDefault(c => c.Type == "sid")?.Value);
        AddClaimIfMissing(identity, "sub", jwt.Subject ?? jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value);
        AddClaimIfMissing(identity, "acr", jwt.Claims.FirstOrDefault(c => c.Type == "acr")?.Value);
        AddClaimIfMissing(identity, "scope", jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value);

        var validationService = context.HttpContext.RequestServices.GetRequiredService<TokenValidationService>();
        var outcome = await validationService.ValidateAsync(context.Principal, context.HttpContext,
            context.HttpContext.RequestAborted);
        if (!outcome.IsSuccess)
        {
            context.Fail(outcome.FailureException
                         ?? new SecurityTokenException(outcome.FailureReason ?? "Token validation failed."));
        }
    }

    private static async Task OnChallengeAsync(JwtBearerChallengeContext context)
    {
        context.HandleResponse();
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/problem+json; charset=utf-8";
        context.Response.Headers.Append("WWW-Authenticate",
            "Bearer error=\"invalid_token\", error_description=\"Authentication required\"");

        // Only a fixed vocabulary is returned: validator exception messages (IDX...) describe key ids,
        // issuers and validation internals and must stay in server logs.
        var detail = context.AuthenticateFailure switch
        {
            null => "Missing or invalid token",
            SecurityTokenExpiredException => "The access token has expired",
            _ => "The access token is invalid"
        };

        var problem = new ProblemDetails
        {
            Type = "/errors/unauthorized",
            Title = "Authentication required",
            Status = StatusCodes.Status401Unauthorized,
            Detail = detail
        };

        await context.Response.WriteAsync(
            JsonSerializer.Serialize(problem, AspNetCoreJsonContext.Default.ProblemDetails),
            context.HttpContext.RequestAborted);
    }

    private static Task OnAuthenticationFailed(AuthenticationFailedContext context)
    {
        if (context.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            var tags = new TagList { { "kid", TryReadKid(context.Request.Headers.Authorization.ToString()) } };
            AuthTelemetry.JwksKidMisses.Add(1, tags);
            AuthTelemetry.JwksRefreshRequests.Add(1);
        }

        return Task.CompletedTask;
    }

    private static string TryReadKid(string authHeader)
    {
        var token = authHeader.StartsWith(DpopScheme, StringComparison.OrdinalIgnoreCase)
            ? authHeader[DpopScheme.Length..]
            : authHeader.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase)
                ? authHeader[BearerScheme.Length..]
                : null;
        if (string.IsNullOrWhiteSpace(token))
        {
            return "unknown";
        }

        try
        {
            return new JsonWebToken(token.Trim()).Kid ?? "unknown";
        }
        catch (ArgumentException)
        {
            // SecurityTokenMalformedException derives from ArgumentException.
            return "unknown";
        }
    }

    private static void AddClaimIfMissing(ClaimsIdentity identity, string type, string? value)
    {
        if (!string.IsNullOrEmpty(value) && !identity.HasClaim(c => c.Type == type))
        {
            identity.AddClaim(new Claim(type, value));
        }
    }
}
