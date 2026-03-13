using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text.Json;

namespace Sentinel.Middleware;

public sealed class MtlsBindingMiddleware(RequestDelegate next, ILogger<MtlsBindingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            await next(context);
            return;
        }

        var cnfClaimValue = context.User.FindFirst("cnf")?.Value;
        if (string.IsNullOrWhiteSpace(cnfClaimValue))
        {
            await next(context);
            return;
        }

        string? expectedThumbprint;
        try
        {
            using var doc = JsonDocument.Parse(cnfClaimValue);
            if (!doc.RootElement.TryGetProperty("x5t#S256", out var thumbprintElement))
            {
                await next(context);
                return;
            }

            expectedThumbprint = thumbprintElement.GetString();
        }
        catch (JsonException)
        {
            logger.LogWarning("Invalid cnf claim JSON for subject {Subject}.", context.User.FindFirst("sub")?.Value);
            await Reject(context, "Invalid cnf claim format.");
            return;
        }

        if (string.IsNullOrWhiteSpace(expectedThumbprint))
        {
            await Reject(context, "Missing certificate thumbprint in cnf claim.");
            return;
        }

        var clientCertificate = await context.Connection.GetClientCertificateAsync();
        if (clientCertificate is null)
        {
            await Reject(context, "Missing required client certificate for mTLS bound token.");
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
