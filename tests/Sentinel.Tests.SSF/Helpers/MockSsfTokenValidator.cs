using System.Text.Json;

namespace Sentinel.Tests.SSF.Helpers;

/// <summary>
/// Mock ISsfTokenValidator for testing.
/// </summary>
public sealed class MockSsfTokenValidator : ISsfTokenValidator
{
    public bool ShouldFail { get; set; }

    public Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
    {
        if (ShouldFail)
        {
            return Task.FromResult(SsfValidationResult.Fail("Mock validation failure"));
        }

        var token = new SsfEventToken(
            Issuer: "https://idp.example.com",
            IssuedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Jti: "test-jti-123",
            Audience: "urn:example:receiver",
            Subject: "user-456",
            Events: new Dictionary<string, JsonElement>());

        return Task.FromResult(SsfValidationResult.Success(token));
    }
}
