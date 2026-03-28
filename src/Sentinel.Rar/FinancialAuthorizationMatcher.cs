using Microsoft.Extensions.Options;
using Sentinel.Domain.Auth.Rar;

namespace Sentinel.RAR;

/// <summary>
///     High-assurance financial authorization matcher.
///     Matches financial transaction authorization constraints against request payloads.
///     Supports transaction ID, amount, and currency bounds per RFC 9396.
/// </summary>
public sealed class FinancialAuthorizationMatcher : IAuthorizationDetailMatcher
{
    /// <summary>Sentinel's canonical financial transfer type (primary).</summary>
    private const string FinancialTransferType = "urn:sentinel:finance:transfer";

    private readonly ILogger<FinancialAuthorizationMatcher> _logger;

    private readonly RarValidationOptions _options;

    /// <summary>
    ///     Initializes a new instance of the FinancialAuthorizationMatcher.
    /// </summary>
    /// <param name="options">Configuration for RAR validation (from DI).</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    /// <remarks>
    ///     ✅ FIX: Strict DI injection via IOptions{RarValidationOptions}.
    ///     Replaces the anti-pattern of nullable options with hard DI guarantees.
    /// </remarks>
    public FinancialAuthorizationMatcher(
        IOptions<RarValidationOptions> options,
        ILogger<FinancialAuthorizationMatcher> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    ///     Matches financial authorization constraints against a request payload.
    /// </summary>
    /// <remarks>
    ///     Checks that:
    ///     - transaction_id (if present in detail) matches payload.transactionId
    ///     - amount (if present in detail) matches payload.amount (with precision tolerance)
    ///     - currency (if present in detail) matches payload.currency
    ///     ✅ FIX: Accepts RarValidationOptions to enable case sensitivity and precision settings.
    /// </remarks>
    public bool Matches(AuthorizationDetail detail, JsonElement payload, RarValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

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

            var tolerance = options.MonetaryPrecisionTolerance;
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
    ///     Gets the support weight for authorization detail types.
    /// </summary>
    /// <remarks>
    ///     Returns high weight for known financial transfer types, 0 for unsupported types.
    ///     Used by RarValidator to route to the most specific matcher implementation.
    ///     ✅ FIX: Only returns non-zero for Sentinel's canonical type.
    ///     Placeholder RFC example URIs are rejected (production safety).
    /// </remarks>
    public int GetSupportWeight(string detailType)
    {
        if (string.IsNullOrWhiteSpace(detailType))
        {
            return 0;
        }

        // ✅ FIX: Only support Sentinel's canonical type, reject RFC placeholders
        return detailType switch
        {
            FinancialTransferType => 100, // Highest priority for Sentinel's type
            _ => 0 // Not supported (including RFC examples)
        };
    }

    /// <summary>
    ///     Extracts a string value from the payload JSON object.
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
    ///     Extracts a decimal value from the payload JSON object.
    ///     Handles both JSON number and string representations of numbers.
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
