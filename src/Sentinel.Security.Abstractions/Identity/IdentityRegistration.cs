namespace Sentinel.Security.Abstractions.Identity;

/// <summary>
/// Provider-agnostic identity registration payload.
/// </summary>
public sealed record IdentityRegistration(
    string Email,
    string Username,
    bool AcceptedTerms,
    string PolicyVersion,
    DateTime AcceptedAtUtc,
    string SourceIp);
