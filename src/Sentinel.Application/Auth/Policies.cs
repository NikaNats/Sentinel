namespace Sentinel.Application.Auth;

/// <summary>
/// Framework-level authorization policy names.
/// Applications should define their own business policy names and register them during configuration.
/// </summary>
public static class Policies
{
    /// <summary>
    /// Requires step-up authentication with ACR level 3 (highest assurance).
    /// Use for sensitive operations like fund transfers or account modifications.
    /// </summary>
    public const string RequireAcr3 = "RequireAcr3";

    /// <summary>
    /// Requires elevated access (application-defined threshold, typically ACR 2+).
    /// Use for moderately sensitive operations.
    /// </summary>
    public const string ElevatedAccess = "ElevatedAccess";
}
