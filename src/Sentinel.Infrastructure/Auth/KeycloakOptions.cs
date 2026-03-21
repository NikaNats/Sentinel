using System.ComponentModel.DataAnnotations;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakOptions
{
    public const string SectionName = "Keycloak";

    [Required] [Url] public string Authority { get; init; } = string.Empty;

    [Required] public string Audience { get; init; } = string.Empty;

    public bool RequireHttpsMetadata { get; init; } = true;

    public int SsoSessionMaxLifespanSeconds { get; init; } = 28_800;

    // Backward-compatible alias for older config shape.
    public int? SessionMaxLifespanSeconds { get; init; }

    public KeycloakAdminOptions Admin { get; init; } = new();

    // Backward-compatible alias for older config shape.
    public string? AdminClientId { get; init; }

    // Backward-compatible alias for older config shape.
    public string? AdminClientSecret { get; init; }
}

public sealed class KeycloakAdminOptions
{
    public string ClientId { get; init; } = string.Empty;

    public string ClientSecret { get; init; } = string.Empty;

    public string? Scope { get; init; }
}
