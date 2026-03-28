using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Domain.Auth.Rar;

/// <summary>
///     Represents a Rich Authorization Request (RAR) authorization detail (RFC 9396).
///     Provides fine-grained, payload-bound authorization constraints for transaction-specific access control.
/// </summary>
/// <remarks>
///     Authorization details allow cryptographic binding of OAuth 2.0 access tokens to specific request parameters:
///     - Financial transfers: Bound to amount, currency, transaction ID
///     - Data exports: Bound to dataset ID, date range, recipient
///     - Medical records: Bound to patient ID, record type, facility
///     This domain model is the canonical source of truth for all RAR systems.
///     Per RFC 9396, authorization details constrain what actions an access token may authorize.
///     Record properties:
///     - Type: Authorization detail type identifier (e.g., "urn:sentinel:finance:transfer")
///     - Actions: Array of actions the authorization permits (e.g., ["read", "write"])
///     - Locations: Array of network locations the authorization permits (e.g., ["https://api.example.com"])
///     - DataTypes: Array of data types the authorization permits (e.g., ["transaction_history", "account_balance"])
///     - TransactionId: Transaction ID for transaction-bound authorization (e.g., financial transfer ID)
///     - Amount: Amount for transaction-bound authorization (e.g., transfer amount in smallest unit)
///     - Currency: Currency code for transaction-bound authorization (ISO 4217, e.g., "USD")
///     - CustomProperties: ✅ Explicit mapping for custom/extension properties, preventing recursive object nesting
/// </remarks>
public sealed record AuthorizationDetail(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("actions")]
    string[]? Actions = null,
    [property: JsonPropertyName("locations")]
    string[]? Locations = null,
    [property: JsonPropertyName("datatypes")]
    string[]? DataTypes = null,
    [property: JsonPropertyName("transaction_id")]
    string? TransactionId = null,
    [property: JsonPropertyName("amount")] decimal? Amount = null,
    [property: JsonPropertyName("currency")]
    string? Currency = null,
    [property: JsonPropertyName("custom_properties")]
    JsonElement? CustomProperties = null);
