using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Errors;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/auth")]
public sealed class TokenExchangeController(ITokenExchangeService tokenExchangeService) : ControllerBase
{
    public sealed record TokenExchangeRequest(string ExternalToken, string ProviderName, string CodeVerifier);

    [HttpPost("token-exchange")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ExchangeExternalToken([FromBody] TokenExchangeRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.ExternalToken)
            || string.IsNullOrWhiteSpace(request.ProviderName)
            || string.IsNullOrWhiteSpace(request.CodeVerifier))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "External token, provider name, and code verifier are required.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var dpopProof = Request.Headers["DPoP"].ToString();
        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "DPoP proof is required.",
                Status = StatusCodes.Status400BadRequest,
                Type = ErrorCodes.MissingDpopProof
            });
        }

        var result = await tokenExchangeService.ExchangeExternalTokenAsync(request.ExternalToken, request.ProviderName, dpopProof, request.CodeVerifier, ct);
        if (result is null || string.IsNullOrWhiteSpace(result.AccessToken))
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Token exchange failed.",
                Status = StatusCodes.Status401Unauthorized
            });
        }

        return Ok(new
        {
            access_token = result.AccessToken,
            refresh_token = result.RefreshToken,
            token_type = result.TokenType,
            expires_in = result.ExpiresIn,
            scope = result.Scope
        });
    }
}
