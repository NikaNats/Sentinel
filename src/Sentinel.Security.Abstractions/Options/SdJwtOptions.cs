namespace Sentinel.Security.Abstractions.Options;

/// <summary>
/// Configuration for Selective Disclosure JWT (SD-JWT) verification.
/// </summary>
public sealed class SdJwtOptions
{
    /// <summary>
    /// Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "SdJwt";

    /// <summary>
    /// Gets or sets whether SD-JWT processing is enabled.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Gets or sets whether key binding is required for presentations.
    /// </summary>
    public bool RequireKeyBindingNonce { get; init; }
}
