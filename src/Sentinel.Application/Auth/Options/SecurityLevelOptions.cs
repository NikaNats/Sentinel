namespace Sentinel.Application.Auth.Options;

/// <summary>
///     Strongly-typed configuration for security level enforcement.
///     Decouples authorization policy from hardcoded strings, enabling
///     Zero Trust architecture where policies are configuration-driven.
/// </summary>
public sealed record SecurityLevelOptions
{
    /// <summary>
    ///     Configuration section name for binding from appsettings.json.
    /// </summary>
    public const string SectionName = "Sentinel:SecurityLevels";

    /// <summary>
    ///     Default minimum ACR (Authentication Context Class Reference) required
    ///     for authenticated users accessing elevated resources.
    /// </summary>
    public string RequiredAcr { get; init; } = "acr3";

    /// <summary>
    ///     Security clearance levels that grant access to elevated resources.
    ///     Examples: "top-secret", "classified", "secret".
    /// </summary>
    public string[] ElevatedClearanceLevels { get; init; } = ["top-secret", "classified"];
}
