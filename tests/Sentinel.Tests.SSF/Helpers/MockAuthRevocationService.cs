namespace Sentinel.Tests.SSF.Helpers;

/// <summary>
/// Mock IAuthRevocationService for testing.
/// </summary>
public sealed class MockAuthRevocationService : IAuthRevocationService
{
    private readonly List<string> _revokedSubjects = [];

    public Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
    {
        _revokedSubjects.Add(subject);
        return Task.CompletedTask;
    }

    public bool WasSubjectRevoked(string subject) => _revokedSubjects.Contains(subject);

    public int RevocationCount => _revokedSubjects.Count;
}
