using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.SSF;

namespace Sentinel.Tests.Shared;

/// <summary>
///     Shared source-generated JSON context for test helpers. With
///     <c>JsonSerializerIsReflectionEnabledByDefault=false</c> the test suite behaves
///     like Native AOT for System.Text.Json, so any test payload serialized without an
///     explicit context fails fast instead of silently using the reflection fallback.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(RarTransferPayload))]
[JsonSerializable(typeof(DocumentCreatePayload))]
[JsonSerializable(typeof(KeycloakIdentityProviderPayload))]
[JsonSerializable(typeof(ChangePasswordRequestPayload))]
[JsonSerializable(typeof(TokenExchangeRequestPayload))]
[JsonSerializable(typeof(SessionRevokedPayload))]
[JsonSerializable(typeof(SsfSetPayload))]
[JsonSerializable(typeof(ProblemDetails))]
[JsonSerializable(typeof(TransferRequest))]
[JsonSerializable(typeof(TransferResponse))]
[JsonSerializable(typeof(KeycloakRealmPayload))]
[JsonSerializable(typeof(KeycloakClientPayload))]
[JsonSerializable(typeof(KeycloakProtocolMapper))]
[JsonSerializable(typeof(VaultSecretDataPayload))]
[JsonSerializable(typeof(VaultPolicyPayload))]
[JsonSerializable(typeof(VaultAuthPayload))]
[JsonSerializable(typeof(VaultConfigPayload))]
[JsonSerializable(typeof(VaultRolePayload))]
public sealed partial class TestJsonContext : JsonSerializerContext
{
}

/// <summary>Wire shape of a finance RAR authorization-detail payload.</summary>
public sealed record RarTransferPayload(string TransactionId, decimal Amount, string Currency);

/// <summary>Wire shape of the documents API create payload.</summary>
public sealed record DocumentCreatePayload(string Title, string Content);

/// <summary>Wire shape of the change-password request (matches <c>AuthEndpoints.ChangePasswordRequest</c>).</summary>
public sealed record ChangePasswordRequestPayload(string NewPassword);

/// <summary>Wire shape of the token-exchange request (matches <c>TokenExchangeEndpoints.TokenExchangeRequest</c>).</summary>
public sealed record TokenExchangeRequestPayload(string ExternalToken, string ProviderName, string CodeVerifier);

/// <summary>Wire shape of a Keycloak identity-provider instance payload (admin API).</summary>
public sealed record KeycloakIdentityProviderPayload(
    string Alias,
    string DisplayName,
    string ProviderId,
    bool Enabled,
    bool TrustEmail,
    bool StoreToken,
    string FirstBrokerLoginFlowAlias,
    Dictionary<string, string> Config);

/// <summary>Wire shape of the Keycloak realm-create payload (admin API).</summary>
public sealed record KeycloakRealmPayload(string Realm, bool Enabled, string SslRequired);

/// <summary>Wire shape of the Keycloak client-create payload (admin API).</summary>
public sealed record KeycloakClientPayload(
    string ClientId,
    string Protocol,
    bool PublicClient,
    string Secret,
    bool DirectAccessGrantsEnabled,
    bool StandardFlowEnabled,
    bool ServiceAccountsEnabled,
    Dictionary<string, string> Attributes,
    KeycloakProtocolMapper[] ProtocolMappers);

/// <summary>Wire shape of a Keycloak protocol-mapper entry (admin API).</summary>
public sealed record KeycloakProtocolMapper(
    string Name,
    string Protocol,
    string ProtocolMapper,
    bool ConsentRequired,
    Dictionary<string, string> Config);

/// <summary>Wire shape of a Vault KV v2 write payload.</summary>
public sealed record VaultSecretDataPayload(Dictionary<string, string> Data);

/// <summary>Wire shape of a Vault ACL policy payload.</summary>
public sealed record VaultPolicyPayload(string Policy);

/// <summary>Wire shape of a Vault auth-backend enable payload.</summary>
public sealed record VaultAuthPayload(string Type, string Description);

/// <summary>Wire shape of a Vault JWT auth configuration payload.</summary>
public sealed record VaultConfigPayload(
    [property: JsonPropertyName("jwt_validation_pubkeys")] string[] JwtValidationPubkeys);

/// <summary>Wire shape of a Vault JWT auth role payload.</summary>
public sealed record VaultRolePayload(
    [property: JsonPropertyName("role_type")] string RoleType,
    [property: JsonPropertyName("user_claim")] string UserClaim,
    [property: JsonPropertyName("bound_subject")] string BoundSubject,
    string[] Policies);