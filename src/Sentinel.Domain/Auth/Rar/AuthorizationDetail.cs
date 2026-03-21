using System.Text.Json.Serialization;

namespace Sentinel.Domain.Auth.Rar;

public sealed record AuthorizationDetail(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("actions")]
    string[]? Actions,
    [property: JsonPropertyName("locations")]
    string[]? Locations,
    [property: JsonPropertyName("datatypes")]
    string[]? DataTypes,
    [property: JsonPropertyName("transaction_id")]
    string? TransactionId,
    [property: JsonPropertyName("amount")] decimal? Amount,
    [property: JsonPropertyName("currency")]
    string? Currency);
