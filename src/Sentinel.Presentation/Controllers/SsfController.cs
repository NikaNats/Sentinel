using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Infrastructure.Auth.Ssf;

namespace Sentinel.Presentation.Controllers;

[ApiController]
[Route("v1/ssf")]
public sealed class SsfController(
    ISsfEventProcessor processor,
    IOptions<SsfOptions> options,
    ILogger<SsfController> logger) : ControllerBase
{
    [HttpPost("events")]
    [AllowAnonymous]
    public async Task<IActionResult> ReceiveEvent(CancellationToken ct)
    {
        var ssfOptions = options.Value;
        if (!ssfOptions.Enabled)
        {
            return NotFound();
        }

        if (ssfOptions.RequireAuthToken && !IsAuthTokenValid(ssfOptions))
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "SSF authentication failed.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        var setToken = await ReadSetTokenAsync(Request, ct);
        if (string.IsNullOrWhiteSpace(setToken))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "SET token is required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var result = await processor.ProcessAsync(setToken, ct);
        if (result.IsSuccess)
        {
            return Accepted();
        }

        logger.LogWarning("SSF event rejected. unauthorized={Unauthorized} error={Error}", result.IsUnauthorized,
            result.Error);

        return result.IsUnauthorized
            ? Unauthorized(new ProblemDetails
            {
                Title = result.Error ?? "Invalid SET.",
                Status = StatusCodes.Status401Unauthorized
            })
            : BadRequest(new ProblemDetails
            {
                Title = result.Error ?? "SET processing failed.",
                Status = StatusCodes.Status400BadRequest
            });
    }

    private bool IsAuthTokenValid(SsfOptions ssfOptions)
    {
        var configuredToken = ssfOptions.AuthToken;
        if (string.IsNullOrWhiteSpace(configuredToken))
        {
            return false;
        }

        var suppliedToken = Request.Headers["SSF-Auth-Token"].ToString();
        if (string.IsNullOrWhiteSpace(suppliedToken))
        {
            return false;
        }

        var configuredBytes = Encoding.UTF8.GetBytes(configuredToken);
        var suppliedBytes = Encoding.UTF8.GetBytes(suppliedToken);
        return CryptographicOperations.FixedTimeEquals(suppliedBytes, configuredBytes);
    }

    private static async Task<string?> ReadSetTokenAsync(HttpRequest request, CancellationToken ct)
    {
        if (request.ContentType?.Contains("application/secevent+jwt", StringComparison.OrdinalIgnoreCase) == true)
        {
            using var reader = new StreamReader(request.Body);
            return (await reader.ReadToEndAsync(ct)).Trim();
        }

        try
        {
            using var payload = await JsonDocument.ParseAsync(request.Body, cancellationToken: ct);
            if (payload.RootElement.TryGetProperty("set", out var setProp))
            {
                return setProp.GetString();
            }

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
