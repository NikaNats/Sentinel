using System.Text.Json;

namespace Sentinel.Security.Abstractions.DPoP;

/// <summary>
/// Request to validate a DPoP proof (RFC 9449).
/// </summary>
public sealed class DpopValidationRequest
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DpopValidationRequest"/> class.
    /// </summary>
    public DpopValidationRequest(
        string dpopHeader,
        string httpMethod,
        Uri httpUri,
        string? accessToken = null,
        string? expectedNonce = null)
    {
        DpopHeader = dpopHeader;
        HttpMethod = httpMethod;
        HttpUri = httpUri;
        AccessToken = accessToken;
        ExpectedNonce = expectedNonce;
    }

    /// <summary>
    /// Gets the raw DPoP proof JWT string.
    /// </summary>
    public string DpopHeader { get; }

    /// <summary>
    /// Gets the HTTP method of the request (uppercase: GET, POST, etc.).
    /// </summary>
    public string HttpMethod { get; }

    /// <summary>
    /// Gets the full request URI (scheme + host + path + query).
    /// </summary>
    public Uri HttpUri { get; }

    /// <summary>
    /// Gets the optional access token being bound to this proof.
    /// </summary>
    public string? AccessToken { get; }

    /// <summary>
    /// Gets the optional nonce challenge from the server.
    /// </summary>
    public string? ExpectedNonce { get; }
}

/// <summary>
/// Success result from DPoP proof validation.
/// </summary>
public sealed class DpopValidationSuccess
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DpopValidationSuccess"/> class.
    /// </summary>
    public DpopValidationSuccess(string newNonce, string thumbprint)
    {
        NewNonce = newNonce;
        Thumbprint = thumbprint;
    }

    /// <summary>
    /// Gets the new nonce to send in the next server response (for nonce challenge-response).
    /// </summary>
    public string NewNonce { get; }

    /// <summary>
    /// Gets the JWK thumbprint of the proof's public key (for cryptographic binding).
    /// </summary>
    public string Thumbprint { get; }

    public override int GetHashCode() => HashCode.Combine(NewNonce, Thumbprint);

    public override bool Equals(object? obj)
        => obj is DpopValidationSuccess other && NewNonce == other.NewNonce && Thumbprint == other.Thumbprint;
}

/// <summary>
/// RFC 9449 DPoP proof validator.
/// </summary>
public interface IDpopProofValidator
{
    /// <summary>
    /// Validates a DPoP proof and returns cryptographic binding information.
    /// </summary>
    /// <param name="request">The validation request containing the proof and HTTP context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success result with nonce and thumbprint, or failure.</returns>
    Task<Results.SecurityResult<DpopValidationSuccess>> ValidateAsync(
        DpopValidationRequest request,
        CancellationToken cancellationToken = default);
}
