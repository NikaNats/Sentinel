using System.Text.Json.Serialization;

namespace Sentinel.RAR;

/// <summary>
/// Represents a Rich Authorization Request (RAR) authorization detail.
/// Per RFC 9396, authorization details provide fine-grained authorization constraints.
/// </summary>
public sealed record AuthorizationDetail(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("actions")] string[]? Actions = null,
    [property: JsonPropertyName("locations")] string[]? Locations = null,
    [property: JsonPropertyName("datatypes")] string[]? DataTypes = null,
    [property: JsonPropertyName("transaction_id")] string? TransactionId = null,
    [property: JsonPropertyName("amount")] decimal? Amount = null,
    [property: JsonPropertyName("currency")] string? Currency = null,
    [property: JsonPropertyName("custom_properties")] JsonElement? CustomProperties = null);

