using System.Text.Json.Serialization;

namespace Sentinel.Security.Abstractions.SSF;

/// <summary>
/// Payload for session-revoked events (https://schemas.openid.net/secevent/caep/event-type/session-revoked).
/// Indicates that a session or subject-level authorization has been revoked.
/// SessionId (optional): The session ID being revoked; if omitted, subject-level revocation.
/// Subject (optional): The subject whose session(s) are revoked; uses main SET subject if omitted.
/// </summary>
public sealed record SessionRevokedPayload(
    [property: JsonPropertyName("sid")] string? SessionId,
    [property: JsonPropertyName("sub")] string? Subject);

/// <summary>
/// Payload for user-status-changed events (https://schemas.openid.net/secevent/caep/event-type/user-status-changed).
/// Indicates that user status has changed (locked, disabled, suspended, etc.).
/// Subject (optional): The subject whose status changed; uses main SET subject if omitted.
/// </summary>
public sealed record UserStatusChangedPayload(
    [property: JsonPropertyName("sub")] string? Subject);

/// <summary>
/// Payload for credential-change events (https://schemas.openid.net/secevent/caep/event-type/credential-change).
/// Indicates that user credentials have been changed or compromised.
/// Subject (optional): The subject whose credentials changed; uses main SET subject if omitted.
/// </summary>
public sealed record CredentialChangePayload(
    [property: JsonPropertyName("sub")] string? Subject);
