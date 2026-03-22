using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Security.Abstractions.SSF;

/// <summary>
/// Represents a Server-Sent Event token (RFC 8936 / CAEP specification).
/// Contains security event information from an identity provider.
/// </summary>
/// <param name="Issuer">The issuer of the event token.</param>
/// <param name="IssuedAt">The time the token was issued (Unix timestamp, seconds).</param>
/// <param name="Jti">The JWT ID claim (unique token identifier).</param>
/// <param name="Audience">The intended audience (usually the event receiver's identifier).</param>
/// <param name="Subject">The subject the event pertains to (optional).</param>
/// <param name="Events">Dictionary of event type URIs to their JSON payloads.</param>
public sealed record SsfEventToken(
    [property: JsonPropertyName("iss")] string Issuer,
    [property: JsonPropertyName("iat")] long IssuedAt,
    [property: JsonPropertyName("jti")] string Jti,
    [property: JsonPropertyName("aud")] string Audience,
    [property: JsonPropertyName("sub")] string? Subject,
    [property: JsonPropertyName("events")] Dictionary<string, JsonElement> Events)
{
    /// <summary>
    /// Gets the IssuedAt time as a DateTimeOffset in UTC.
    /// </summary>
    public DateTimeOffset IssuedAtDateTimeOffset => DateTimeOffset.FromUnixTimeSeconds(IssuedAt);
}
