namespace Sentinel.Security.Abstractions.DPoP;

/// <summary>
///     DPoP proof validation result. Moved here from Application layer per NuGet boundaries.
/// </summary>
public sealed class DpopValidationResult
{
    public bool IsValid { get; set; }
    public string NewNonce { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}
