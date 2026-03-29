using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.AspNetCore.Middleware;

public sealed class MtlsBindingMiddleware(RequestDelegate next, ILogger<MtlsBindingMiddleware> logger)
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var expectedThumbprint = TryResolveExpectedThumbprint(context, logger);
        if (string.IsNullOrWhiteSpace(expectedThumbprint))
        {
            await next(context);
            return;
        }

        var clientCertificate = await context.Connection.GetClientCertificateAsync();
        if (clientCertificate is null)
        {
            await Reject(context, "Missing required client certificate for mTLS binding.");
            return;
        }

        var actualThumbprint = Base64UrlEncoder.Encode(clientCertificate.GetCertHash(HashAlgorithmName.SHA256));
        if (!string.Equals(expectedThumbprint, actualThumbprint, StringComparison.Ordinal))
        {
            logger.LogCritical(
                "mTLS binding mismatch for subject {Subject}. expected_x5t={Expected}, actual_x5t={Actual}",
                context.User.FindFirst("sub")?.Value,
                expectedThumbprint,
                actualThumbprint);

            await Reject(context, "Certificate thumbprint mismatch.");
            return;
        }

        await next(context);
    }

    private static string? TryResolveExpectedThumbprint(HttpContext context, ILogger logger)
    {
        if (TryGetThumbprintFromAuthenticatedPrincipal(context, logger, out var thumbprintFromPrincipal))
        {
            return thumbprintFromPrincipal;
        }

        return TryGetThumbprintFromAccessToken(context, logger);
    }

    private static bool TryGetThumbprintFromAuthenticatedPrincipal(
        HttpContext context,
        ILogger logger,
        out string? thumbprint)
    {
        thumbprint = null;

        if (context.User.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var cnfClaimValue = context.User.FindFirst("cnf")?.Value;
        if (string.IsNullOrWhiteSpace(cnfClaimValue))
        {
            return false;
        }

        thumbprint = TryParseThumbprint(cnfClaimValue, logger, context.User.FindFirst("sub")?.Value);
        return true;
    }

    private static string? TryGetThumbprintFromAccessToken(HttpContext context, ILogger logger)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authHeader))
        {
            return null;
        }

        string token;
        if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["DPoP ".Length..].Trim();
        }
        else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["Bearer ".Length..].Trim();
        }
        else
        {
            return null;
        }

        if (!TokenHandler.CanReadToken(token))
        {
            return null;
        }

        var jwt = TokenHandler.ReadJsonWebToken(token);
        if (!jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnfElement) ||
            cnfElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return cnfElement.TryGetProperty("x5t#S256", out var thumbprintElement)
            ? thumbprintElement.GetString()
            : null;
    }

    private static string? TryParseThumbprint(string cnfClaimValue, ILogger logger, string? subject)
    {
        try
        {
            using var doc = JsonDocument.Parse(cnfClaimValue);
            if (!doc.RootElement.TryGetProperty("x5t#S256", out var thumbprintElement))
            {
                return null;
            }

            return thumbprintElement.GetString();
        }
        catch (JsonException)
        {
            logger.LogWarning("Invalid cnf claim JSON for subject {Subject}.", subject);
            return null;
        }
    }

    private static async Task Reject(HttpContext context, string detail)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Type = "/errors/mtls-binding-failed",
            Title = "Certificate Binding Error",
            Detail = detail,
            Status = StatusCodes.Status403Forbidden
        });
    }
}
