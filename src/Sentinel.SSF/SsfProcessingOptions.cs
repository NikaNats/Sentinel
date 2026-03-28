namespace Sentinel.SSF;

/// <summary>
///     Configuration options for Server-Sent Event (SSF/CAEP) processing.
/// </summary>
public sealed class SsfProcessingOptions
{
    /// <summary>
    ///     Gets or sets the TTL (time-to-live) in seconds for session revocations.
    ///     Sessions blacklisted due to SSF events will not be valid after this period.
    ///     Default: 28,800 seconds (8 hours).
    /// </summary>
    public int SessionRevocationTtlSeconds { get; init; } = 28_800;

    /// <summary>
    ///     Gets or sets the maximum age in seconds for a SET token.
    ///     Tokens with an iat claim older than this are rejected.
    ///     Default: 300 seconds (5 minutes).
    /// </summary>
    public int MaxEventAgeSeconds { get; init; } = 300;

    /// <summary>
    ///     Gets or sets the allowed clock skew in seconds for iat validation.
    ///     Helps accommodate minor time synchronization differences between systems.
    ///     Default: 300 seconds (5 minutes).
    /// </summary>
    public int AllowedClockSkewSeconds { get; init; } = 300;
}
