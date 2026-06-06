using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.SdJwt;

namespace Sentinel.Sample.MinimalApi;

/// <summary>
///     Minimal stub implementation of ISdJwtTokenValidator for demonstration/testing.
/// </summary>
internal sealed class SampleSdJwtTokenValidator : ISdJwtTokenValidator
{
    private readonly TokenValidationParameters _parameters;

    public SampleSdJwtTokenValidator(IOptions<SdJwtVerificationOptions> options)
    {
        _parameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(options.Value.AllowedClockSkewSeconds)
        };
    }

    public async Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
        string issuerJwt,
        string expectedAudience,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var handler = new JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(issuerJwt, _parameters);
            if (result.IsValid)
            {
                var token = new JsonWebToken(issuerJwt);
                return SdJwtIssuerTokenValidationResult.Success(token);
            }

            return SdJwtIssuerTokenValidationResult.Failure(result.Exception?.Message ?? "Invalid token");
        }
        catch (SecurityTokenException ex)
        {
            return SdJwtIssuerTokenValidationResult.Failure(ex.Message);
        }
    }
}
