namespace Sentinel.Domain.Users;

public sealed record ConsentInfo(
    bool TermsAccepted,
    string PrivacyPolicyVersion,
    DateTime AcceptedAtUtc,
    string IpAddress);
