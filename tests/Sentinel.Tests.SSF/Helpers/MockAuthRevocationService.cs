namespace Sentinel.Tests.SSF.Helpers;

/// <summary>
///     Mock IAuthRevocationService for testing.
/// </summary>
public sealed class MockAuthRevocationService : IAuthRevocationService
{
    private readonly List<string> _revokedSubjects = [];

    public int RevocationCount => _revokedSubjects.Count;

    public Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
    {
        _revokedSubjects.Add(subject);
        return Task.CompletedTask;
    }

    public bool WasSubjectRevoked(string subject) => _revokedSubjects.Contains(subject);
}
