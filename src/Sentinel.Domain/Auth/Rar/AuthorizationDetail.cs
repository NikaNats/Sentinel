using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Domain.Auth.Rar;

/// <summary>
/// Represents a Rich Authorization Request (RAR) authorization detail (RFC 9396).
/// Provides fine-grained, payload-bound authorization constraints for transaction-specific access control.
/// </summary>
/// <remarks>
/// Authorization details allow cryptographic binding of OAuth 2.0 access tokens to specific request parameters:
/// - Financial transfers: Bound to amount, currency, transaction ID
/// - Data exports: Bound to dataset ID, date range, recipient
/// - Medical records: Bound to patient ID, record type, facility
///
/// This domain model is the canonical source of truth for all RAR systems.
/// Per RFC 9396, authorization details constrain what actions an access token may authorize.
/// </remarks>
public sealed record AuthorizationDetail(
    /// <summary>Authorization detail type identifier (e.g., "urn:sentinel:finance:transfer").</summary>
    [property: JsonPropertyName("type")] string Type,
    /// <summary>Array of actions the authorization permits (e.g., ["read", "write"]).</summary>
    [property: JsonPropertyName("actions")] string[]? Actions = null,
    /// <summary>Array of network locations the authorization permits (e.g., ["https://api.example.com"]).</summary>
    [property: JsonPropertyName("locations")] string[]? Locations = null,
    /// <summary>Array of data types the authorization permits (e.g., ["transaction_history", "account_balance"]).</summary>
    [property: JsonPropertyName("datatypes")] string[]? DataTypes = null,
    /// <summary>Transaction ID for transaction-bound authorization (e.g., financial transfer ID).</summary>
    [property: JsonPropertyName("transaction_id")] string? TransactionId = null,
    /// <summary>Amount for transaction-bound authorization (e.g., transfer amount in smallest unit).</summary>
    [property: JsonPropertyName("amount")] decimal? Amount = null,
    /// <summary>Currency code for transaction-bound authorization (ISO 4217, e.g., "USD").</summary>
    [property: JsonPropertyName("currency")] string? Currency = null,
    /// <summary>✅ FIX: Explicit mapping for custom/extension properties, preventing recursive object nesting.</summary>
    [property: JsonPropertyName("custom_properties")] JsonElement? CustomProperties = null);
