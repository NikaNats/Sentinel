namespace Sentinel.RAR;

/// <summary>
/// Represents a Rich Authorization Request (RAR) authorization detail.
/// Per RFC 9396, authorization details provide fine-grained authorization constraints.
/// </summary>
public sealed record AuthorizationDetail(
    string Type,
    string[]? Actions = null,
    string[]? Locations = null,
    string[]? DataTypes = null,
    string? TransactionId = null,
    decimal? Amount = null,
    string? Currency = null,
    JsonElement? CustomProperties = null)
{
    /// <summary>
    /// Gets the type/category of this authorization detail (e.g., "urn:example:transfer").
    /// </summary>
    public string Type { get; } = Type ?? throw new ArgumentNullException(nameof(Type));

    /// <summary>
    /// Gets the types of actions this authorization permits.
    /// </summary>
    public string[]? Actions { get; } = Actions;

    /// <summary>
    /// Gets the geographic or logical locations this authorization applies to.
    /// </summary>
    public string[]? Locations { get; } = Locations;

    /// <summary>
    /// Gets the data types this authorization permits access to.
    /// </summary>
    public string[]? DataTypes { get; } = DataTypes;

    /// <summary>
    /// Gets the transaction ID this authorization is bound to.
    /// </summary>
    public string? TransactionId { get; } = TransactionId;

    /// <summary>
    /// Gets the monetary amount this authorization permits.
    /// </summary>
    public decimal? Amount { get; } = Amount;

    /// <summary>
    /// Gets the currency code for the authorized amount (ISO 4217).
    /// </summary>
    public string? Currency { get; } = Currency;

    /// <summary>
    /// Gets any custom properties passed through authorization details.
    /// </summary>
    public JsonElement? CustomProperties { get; } = CustomProperties;
}
