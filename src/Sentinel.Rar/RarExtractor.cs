namespace Sentinel.RAR;

/// <summary>
/// Extracts and parses Rich Authorization Request (RAR) authorization_details claims.
/// </summary>
public sealed class RarExtractor : IRarExtractor
{
    private readonly RarValidationOptions _options;
    private readonly ILogger<RarExtractor> _logger;

    /// <summary>
    /// Initializes a new instance of the RarExtractor.
    /// </summary>
    /// <param name="options">Configuration for RAR validation.</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    public RarExtractor(
        RarValidationOptions? options = null,
        ILogger<RarExtractor>? logger = null)
    {
        _options = options ?? new RarValidationOptions();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RarExtractor>.Instance;
    }

    /// <summary>
    /// Extracts and parses authorization details from the JSON claim value.
    /// </summary>
    public RarExtractionResult Extract(string claimsJson)
    {
        if (string.IsNullOrWhiteSpace(claimsJson))
        {
            return RarExtractionResult.Success([]);
        }

        try
        {
            using var doc = JsonDocument.Parse(claimsJson);

            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                _logger.LogWarning("Authorization details claim is not a JSON array");
                return RarExtractionResult.Failure("Authorization details must be a JSON array.");
            }

            var count = doc.RootElement.GetArrayLength();
            if (count > _options.MaxAuthorizationDetailsCount)
            {
                _logger.LogWarning(
                    "Authorization details count exceeds limit (count: {Count}, max: {Max})",
                    count, _options.MaxAuthorizationDetailsCount);
                return RarExtractionResult.Failure(
                    $"Authorization details exceeds maximum count ({_options.MaxAuthorizationDetailsCount}).");
            }

            var details = new List<AuthorizationDetail>(count);

            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (!TryParseDetail(element, out var detail))
                {
                    _logger.LogWarning("Failed to parse authorization detail element");
                    continue;
                }

                details.Add(detail);
            }

            return RarExtractionResult.Success(details.ToArray());
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse authorization_details claim as JSON");
            return RarExtractionResult.Failure("Authorization details claim is not valid JSON.");
        }
#pragma warning disable CA1031  // Continue extraction even if one detail fails
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during authorization details extraction");
            return RarExtractionResult.Failure("Authorization details extraction failed.");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Parses a single authorization detail object.
    /// </summary>
    private static bool TryParseDetail(JsonElement element, [NotNullWhen(true)] out AuthorizationDetail? detail)
    {
        detail = null;

        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        // Type is required
        if (!element.TryGetProperty("type", out var typeElement))
        {
            return false;
        }

        var type = typeElement.GetString();
        if (string.IsNullOrWhiteSpace(type))
        {
            return false;
        }

        // Parse optional string arrays
        var actions = TryParseStringArray(element, "actions");
        var locations = TryParseStringArray(element, "locations");
        var dataTypes = TryParseStringArray(element, "datatypes");

        // Parse optional financial fields
        string? transactionId = null;
        decimal? amount = null;
        string? currency = null;

        if (element.TryGetProperty("transaction_id", out var txIdElement))
        {
            transactionId = txIdElement.GetString();
        }

        if (element.TryGetProperty("amount", out var amountElement))
        {
            if (amountElement.TryGetDecimal(out var amountValue))
            {
                amount = amountValue;
            }
        }

        if (element.TryGetProperty("currency", out var currencyElement))
        {
            currency = currencyElement.GetString();
        }

        // Preserve any custom properties
        JsonElement? customProps = element;

        detail = new AuthorizationDetail(
            type,
            actions,
            locations,
            dataTypes,
            transactionId,
            amount,
            currency,
            customProps);

        return true;
    }

    /// <summary>
    /// Parses a string array from a JSON object property.
    /// </summary>
    private static string[]? TryParseStringArray(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var arrayElement))
        {
            return null;
        }

        if (arrayElement.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var items = new List<string>();
        foreach (var item in arrayElement.EnumerateArray())
        {
            var str = item.GetString();
            if (!string.IsNullOrWhiteSpace(str))
            {
                items.Add(str);
            }
        }

        return items.Count > 0 ? items.ToArray() : null;
    }
}
