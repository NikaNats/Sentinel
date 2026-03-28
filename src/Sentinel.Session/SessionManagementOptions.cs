namespace Sentinel.Session;

/// <summary>
///     Configuration for session management behavior.
/// </summary>
public sealed class SessionManagementOptions
{
    public const string SectionName = "SessionManagement";

    /// <summary>
    ///     If true, sessions track the DPoP thumbprint and validate it on each request.
    /// </summary>
    public bool RequireDpopBinding { get; set; } = true;

    /// <summary>
    ///     Default session lifetime if not specified by the Identity Provider.
    /// </summary>
    public TimeSpan SessionMaxLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    ///     Cleanup interval for expired session blacklist entries.
    /// </summary>
    public TimeSpan BlacklistCleanupInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
///     Startup validation for session management options.
///     Ensures the application fails fast if configured insecurely.
/// </summary>
public sealed class SessionManagementOptionsValidator : IValidateOptions<SessionManagementOptions>
{
    /// <summary>
    ///     Validates session management options at startup.
    /// </summary>
    public ValidateOptionsResult Validate(string? name, SessionManagementOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // ✅ GUARD: Session lifetime must be positive
        if (options.SessionMaxLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.SessionMaxLifetime)} must be greater than zero. Configured: {options.SessionMaxLifetime}");
        }

        // ✅ GUARD: Cleanup interval must be positive
        if (options.BlacklistCleanupInterval <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.BlacklistCleanupInterval)} must be greater than zero. Configured: {options.BlacklistCleanupInterval}");
        }

        return ValidateOptionsResult.Success;
    }
}
