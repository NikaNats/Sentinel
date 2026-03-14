namespace Sentinel.Application.Common.Abstractions;

public interface IDpopProofValidator
{
    Task<DpopValidationResult> ValidateAsync(string dpopHeader, string accessToken, string httpMethod, string httpUrl, string? expectedNonce, CancellationToken ct);
}

public sealed class DpopValidationResult
{
    public bool IsValid { get; set; }
    public string NewNonce { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}
