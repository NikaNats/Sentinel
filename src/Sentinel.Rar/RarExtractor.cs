using Microsoft.Extensions.Options;

namespace Sentinel.RAR;

/// <summary>
///     High-assurance RAR extractor with Native AOT compatibility.
///     Extracts and parses Rich Authorization Request (RAR) authorization_details claims
///     using source-generated JSON deserialization (zero reflection, zero recursion).
/// </summary>
public sealed class RarExtractor : IRarExtractor
{
    private readonly ILogger<RarExtractor> _logger;
    private readonly RarValidationOptions _options;

    /// <summary>
    ///     Initializes a new instance of the RarExtractor.
    /// </summary>
    /// <param name="options">Configuration for RAR validation (from DI).</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    /// <remarks>
    ///     ✅ FIX: Strict DI injection via IOptions{RarValidationOptions}.
    ///     Replaces the anti-pattern of nullable options with hard DI guarantees.
    /// </remarks>
    public RarExtractor(
        IOptions<RarValidationOptions> options,
        ILogger<RarExtractor> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    ///     Extracts and parses authorization details from the JSON claim value.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Use Native AOT Source-Generated deserialization.
    ///     Eliminates the manual, recursive-prone JsonElement traversal.
    ///     Deserializes AuthorizationDetail[] directly from JSON string using RarJsonContext.
    /// </remarks>
    /// <param name="claimsJson">The JSON string from the authorization_details claim.</param>
    /// <returns>Extraction result containing parsed details or error information.</returns>
    public RarExtractionResult Extract(string claimsJson)
    {
        if (string.IsNullOrWhiteSpace(claimsJson))
        {
            return RarExtractionResult.Success([]);
        }

        try
        {
            // ✅ FIX: Use Native AOT Source-Generated deserialization.
            // Deserializes directly from JsonElement without manual traversal.
            var details = JsonSerializer.Deserialize(
                claimsJson,
                RarJsonContext.Default.AuthorizationDetailArray);

            if (details is null)
            {
                _logger.LogWarning("Authorization details deserialization returned null");
                return RarExtractionResult.Failure("Authorization details must be a JSON array.");
            }

            if (details.Length > _options.MaxAuthorizationDetailsCount)
            {
                _logger.LogWarning(
                    "Authorization details count exceeds limit (count: {Count}, max: {Max})",
                    details.Length, _options.MaxAuthorizationDetailsCount);
                return RarExtractionResult.Failure(
                    $"Authorization details exceed maximum count ({_options.MaxAuthorizationDetailsCount}).");
            }

            return RarExtractionResult.Success(details);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse authorization_details claim as JSON");
            return RarExtractionResult.Failure("Authorization details claim is not valid JSON.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Unexpected error during authorization details extraction");
            return RarExtractionResult.Failure("Authorization details extraction failed.");
        }
    }
}
