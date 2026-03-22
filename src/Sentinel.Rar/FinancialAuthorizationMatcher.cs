namespace Sentinel.RAR;

/// <summary>
/// Default authorization detail matcher for financial transfer authorization details.
/// Supports matching transaction ID, amount, and currency constraints.
/// </summary>
public sealed class FinancialAuthorizationMatcher : IAuthorizationDetailMatcher
{
    private const string FinancialTransferType = "urn:sentinel:finance:transfer";
    private const string GenericFinanceType = "urn:example:finance:transfer";

    private readonly RarValidationOptions _options;
    private readonly ILogger<FinancialAuthorizationMatcher> _logger;

    /// <summary>
    /// Initializes a new instance of the FinancialAuthorizationMatcher.
    /// </summary>
    /// <param name="options">Configuration for RAR validation.</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    public FinancialAuthorizationMatcher(
        RarValidationOptions? options = null,
        ILogger<FinancialAuthorizationMatcher>? logger = null)
    {
        _options = options ?? new RarValidationOptions();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<FinancialAuthorizationMatcher>.Instance;
    }

    /// <summary>
    /// Matches financial authorization constraints against a request payload.
    /// </summary>
    /// <remarks>
    /// Checks that:
    /// - transaction_id (if present in detail) matches payload.transactionId
    /// - amount (if present in detail) matches payload.amount (with precision tolerance)
    /// - currency (if present in detail) matches payload.currency
    /// </remarks>
    public bool Matches(AuthorizationDetail detail, JsonElement payload)
    {
        if (detail is null || payload.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        // Check transaction ID
        if (!string.IsNullOrWhiteSpace(detail.TransactionId))
        {
            if (!TryGetPayloadString(payload, "transactionId", out var payloadTxId)
                || !string.Equals(detail.TransactionId, payloadTxId, StringComparison.Ordinal))
            {
                _logger.LogWarning("Transaction ID mismatch (expected: {Expected}, got: {Actual})",
                    detail.TransactionId, payloadTxId ?? "<missing>");
                return false;
            }
        }

        // Check amount (with precision tolerance for financial data)
        if (detail.Amount.HasValue)
        {
            if (!TryGetPayloadDecimal(payload, "amount", out var payloadAmount))
            {
                _logger.LogWarning("Amount field missing or invalid in payload");
                return false;
            }

            var tolerance = _options.MonetaryPrecisionTolerance;
            if (Math.Abs(detail.Amount.Value - payloadAmount) > tolerance)
            {
                _logger.LogWarning("Amount mismatch (expected: {Expected}, got: {Actual})",
                    detail.Amount.Value, payloadAmount);
                return false;
            }
        }

        // Check currency (case-insensitive for ISO 4217 codes)
        if (!string.IsNullOrWhiteSpace(detail.Currency))
        {
            if (!TryGetPayloadString(payload, "currency", out var payloadCurrency)
                || !string.Equals(detail.Currency, payloadCurrency, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Currency mismatch (expected: {Expected}, got: {Actual})",
                    detail.Currency, payloadCurrency ?? "<missing>");
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Gets the support weight for authorization detail types.
    /// Returns high weight for known financial transfer types, 0 for unsupported types.
    /// </summary>
    public int GetSupportWeight(string detailType)
    {
        if (string.IsNullOrWhiteSpace(detailType))
        {
            return 0;
        }

        return detailType switch
        {
            FinancialTransferType => 100,  // Highest priority for Sentinel's type
            GenericFinanceType => 50,      // Second priority for generic examples
            _ => 0                          // Not supported
        };
    }

    /// <summary>
    /// Extracts a string value from the payload JSON object.
    /// </summary>
    private static bool TryGetPayloadString(
        JsonElement payload,
        string propertyName,
        [NotNullWhen(true)] out string? value)
    {
        value = null;

        if (!payload.TryGetProperty(propertyName, out var element))
        {
            return false;
        }

        value = element.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// Extracts a decimal value from the payload JSON object.
    /// Handles both JSON number and string representations of numbers.
    /// </summary>
    private static bool TryGetPayloadDecimal(
        JsonElement payload,
        string propertyName,
        out decimal value)
    {
        value = 0m;

        if (!payload.TryGetProperty(propertyName, out var element))
        {
            return false;
        }

        return element.ValueKind switch
        {
            JsonValueKind.Number => element.TryGetDecimal(out value),
            JsonValueKind.String => decimal.TryParse(element.GetString(), out value),
            _ => false
        };
    }
}
