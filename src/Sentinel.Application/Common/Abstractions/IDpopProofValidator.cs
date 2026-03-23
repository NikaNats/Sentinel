// DEPRECATED: Use Sentinel.Security.Abstractions.DPoP.IDpopProofValidator and DpopValidationSuccess instead.
// This file maintained for backward compatibility during migration to NuGet boundaries.

using Sentinel.Security.Abstractions.DPoP;

namespace Sentinel.Application.Common.Abstractions;

#pragma warning disable CS0618 // Type is obsolete
public interface IDpopProofValidator : Sentinel.Security.Abstractions.DPoP.IDpopProofValidator
{
}
#pragma warning restore CS0618

/// <summary>
/// Legacy result type - use DpopValidationSuccess from Security.Abstractions instead.
/// </summary>
public sealed class DpopValidationResult
{
    public bool IsValid { get; set; }
    public string NewNonce { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}
