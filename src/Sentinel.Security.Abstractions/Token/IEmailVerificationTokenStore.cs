namespace Sentinel.Security.Abstractions.Token;

/// <summary>
///     Stores and consumes email verification tokens (one-time tokens for email confirmation).
///     Enforces single-use semantics and TTL-based expiration.
/// </summary>
public interface IEmailVerificationTokenStore
{
    /// <summary>
    ///     Stores an email verification token with TTL enforcement.
    /// </summary>
    /// <param name="token">The verification token (typically a CSPRNG-generated string).</param>
    /// <param name="keycloakUserId">The Keycloak user ID associated with this verification.</param>
    /// <param name="ttl">Time-to-live for the token (e.g., 24 hours).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if stored successfully, false if token already exists or storage fails.</returns>
    Task<bool> StoreAsync(string token, string keycloakUserId, TimeSpan ttl, CancellationToken ct);

    /// <summary>
    ///     Consumes (and removes) an email verification token if valid.
    ///     Enforces single-use semantics: token is deleted after consumption.
    /// </summary>
    /// <param name="token">The verification token to consume.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The Keycloak user ID if token is valid and not expired, null otherwise.</returns>
    Task<string?> ConsumeAsync(string token, CancellationToken ct);
}
