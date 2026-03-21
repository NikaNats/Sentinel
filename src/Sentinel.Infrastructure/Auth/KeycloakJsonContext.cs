using System.Text.Json.Serialization;

namespace Sentinel.Infrastructure.Auth;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(List<KeycloakUserResponse>))]
[JsonSerializable(typeof(KeycloakAdminCreateUserPayload))]
[JsonSerializable(typeof(KeycloakAdminCredentialPayload))]
[JsonSerializable(typeof(KeycloakAdminUserUpdatePayload))]
[JsonSerializable(typeof(KeycloakAdminPasswordResetPayload))]
[JsonSerializable(typeof(KeycloakIdentityProviderPayload))]
internal sealed partial class KeycloakJsonContext : JsonSerializerContext
{
}

internal sealed class KeycloakUserResponse
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? Username { get; set; }
}

internal sealed class KeycloakAdminCreateUserPayload
{
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool EmailVerified { get; set; }
    public List<KeycloakAdminCredentialPayload> Credentials { get; set; } = [];
    public Dictionary<string, string[]> Attributes { get; set; } = [];
}

internal sealed class KeycloakAdminCredentialPayload
{
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public bool Temporary { get; set; }
}

internal sealed class KeycloakAdminUserUpdatePayload
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool? EmailVerified { get; set; }
    public Dictionary<string, string[]>? Attributes { get; set; }
}

internal sealed class KeycloakAdminPasswordResetPayload
{
    public string Type { get; set; } = "password";
    public string Value { get; set; } = string.Empty;
    public bool Temporary { get; set; }
}

internal sealed class KeycloakIdentityProviderPayload
{
    public string Alias { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ProviderId { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool TrustEmail { get; set; }
    public bool StoreToken { get; set; }
    public string FirstBrokerLoginFlowAlias { get; set; } = "first broker login";
    public Dictionary<string, string> Config { get; set; } = [];
}
