namespace Sentinel.Application.Common.Abstractions;

// DEPRECATED: Use Sentinel.Security.Abstractions.DPoP.IDpopProofValidator and DpopValidationResult instead.
// This is a compatibility shim to avoid breaking existing code during migration to NuGet boundaries.

public interface IDpopProofValidator
{
    Task<DpopValidationResult> ValidateAsync(string dpopHeader, string accessToken, string httpMethod, string httpUrl,
        string? expectedNonce, CancellationToken ct);
}

public sealed class DpopValidationResult
{
    public bool IsValid { get; set; }
    public string NewNonce { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}
