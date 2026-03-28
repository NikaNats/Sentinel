using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;
using Sentinel.Keycloak.Models;

namespace Sentinel.Keycloak;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(List<KeycloakUserResponse>))]
[JsonSerializable(typeof(KeycloakAdminCreateUserPayload))]
[JsonSerializable(typeof(KeycloakAdminCredentialPayload))]
[JsonSerializable(typeof(KeycloakAdminUserUpdatePayload))]
[JsonSerializable(typeof(KeycloakAdminPasswordResetPayload))]
[JsonSerializable(typeof(KeycloakIdentityProviderPayload))]
// ✅ FIX: Added missing hot-path types for Native AOT with source generation
[JsonSerializable(typeof(KeycloakToken))]
[JsonSerializable(typeof(KeycloakSubject))]
[JsonSerializable(typeof(KeycloakAdminDisablePayload))]
// ✅ FIX: Added dictionary type for configuration manager
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
public sealed partial class KeycloakJsonContext : JsonSerializerContext
{
}

public sealed class KeycloakUserResponse
{
    public string? Id { get; set; }
    public string? Email { get; set; }
    public string? Username { get; set; }
}

public sealed class KeycloakAdminCreateUserPayload
{
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool EmailVerified { get; set; }
#pragma warning disable CA2227, CA1002
    public List<KeycloakAdminCredentialPayload> Credentials { get; set; } = [];
#pragma warning restore CA2227, CA1002
#pragma warning disable CA2227
    public Dictionary<string, string[]> Attributes { get; set; } = [];
#pragma warning restore CA2227
}

public sealed class KeycloakAdminCredentialPayload
{
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public bool Temporary { get; set; }
}

public sealed class KeycloakAdminUserUpdatePayload
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool? EmailVerified { get; set; }
#pragma warning disable CA2227
    public Dictionary<string, string[]>? Attributes { get; set; }
#pragma warning restore CA2227
}

public sealed class KeycloakAdminPasswordResetPayload
{
    public string Type { get; set; } = "password";
    public string Value { get; set; } = string.Empty;
    public bool Temporary { get; set; }
}

public sealed class KeycloakIdentityProviderPayload
{
    public string Alias { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ProviderId { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool TrustEmail { get; set; }
    public bool StoreToken { get; set; }
    public string FirstBrokerLoginFlowAlias { get; set; } = "first broker login";
#pragma warning disable CA2227
    public Dictionary<string, string> Config { get; set; } = [];
#pragma warning restore CA2227
}

/// <summary>
/// ✅ FIX: Typed payload to replace anonymous object { Enabled = value } in user disable operations.
/// Enables source-generated JSON serialization instead of reflection.
/// </summary>
public sealed class KeycloakAdminDisablePayload
{
    public bool Enabled { get; set; }
}
