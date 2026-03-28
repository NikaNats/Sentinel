namespace Sentinel.Keycloak.Models;

/// <summary>
///     Keycloak token representation.
/// </summary>
public sealed record KeycloakToken
{
    [JsonPropertyName("access_token")] public string AccessToken { get; init; } = string.Empty;

    [JsonPropertyName("expires_in")] public int ExpiresIn { get; init; }

    [JsonPropertyName("refresh_expires_in")]
    public int? RefreshExpiresIn { get; init; }

    [JsonPropertyName("refresh_token")] public string? RefreshToken { get; init; }

    [JsonPropertyName("token_type")] public string TokenType { get; init; } = "Bearer";
}

/// <summary>
///     Subject representation for token revocation.
/// </summary>
public sealed record KeycloakSubject
{
    [JsonPropertyName("id")] public string Id { get; init; } = string.Empty;

    [JsonPropertyName("username")] public string? Username { get; init; }

    [JsonPropertyName("email")] public string? Email { get; init; }

    [JsonPropertyName("firstName")] public string? FirstName { get; init; }

    [JsonPropertyName("lastName")] public string? LastName { get; init; }
}
