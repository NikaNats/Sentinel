using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.AspNetCore;

/// <summary>
/// Adapts the SecurityResult&lt;DpopValidationSuccess&gt; from the DPoP proof validator
/// to the HTTP-friendly DpopValidationResult used in ASP.NET Core middleware and controllers.
/// </summary>
public static class DpopValidationResultAdapter
{
    /// <summary>
    /// Converts a DPoP proof validation result from the internal domain model to the HTTP layer model.
    /// Extension method for fluent conversion.
    /// </summary>
    /// <param name="validationResult">The security result from DPoP validation.</param>
    /// <returns>A converted validation result suitable for HTTP responses.</returns>
    public static DpopValidationResult ToHttpResult(this SecurityResult<DpopValidationSuccess> validationResult)
    {
        if (validationResult.IsSuccess)
        {
            var success = validationResult.Value;
            return new DpopValidationResult
            {
                IsValid = true,
                NewNonce = success.NewNonce,
                Error = string.Empty
            };
        }

        return new DpopValidationResult
        {
            IsValid = false,
            NewNonce = string.Empty,
            Error = validationResult.ErrorMessage ?? "unknown_error"
        };
    }
}
