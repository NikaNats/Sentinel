namespace Sentinel.Security.Abstractions.Secrets;

/// <summary>
///     Provides reading of secrets from an external secure store (Vault, Azure KV, AWS Secrets).
/// </summary>
public interface ISecretProvider
{
    /// <summary>
    ///     Asynchronously retrieves a secret value for a given path and key.
    /// </summary>
    ValueTask<string?> GetSecretAsync(string secretPath, string key, CancellationToken cancellationToken = default);
}
