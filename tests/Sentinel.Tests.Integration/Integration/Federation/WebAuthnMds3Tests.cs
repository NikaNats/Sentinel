using FluentAssertions;
using Microsoft.Playwright;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     ADR-2026-006 Pillar 2: Hermetic attestation-trust enforcement (FR-10).
///     Proves that under "direct" attestation policy, an untrusted authenticator
///     (CDP virtual authenticator's self-signed packed attestation) is rejected with "invalid cert path".
/// </summary>
[Collection(WebAuthnAal3Collection.Name)]
public sealed class WebAuthnMds3Tests : IAsyncLifetime
{
    private readonly WebAuthnAal3Fixture _fixture;
    private readonly ITestOutputHelper _output;

    public WebAuthnMds3Tests(WebAuthnAal3Fixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
        _output = output ?? throw new ArgumentNullException(nameof(output));
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact(DisplayName = "FR-10: Rogue authenticator under direct policy is rejected fail-closed")]
    public async Task RogueAuthenticator_UnderDirectPolicy_IsRejectedFailClosed()
    {
        // Arrange: Prove the MDS3 mock is live before testing
        var blobJwt = await _fixture.ProbeMds3MockAsync();
        blobJwt.Should().NotBeNullOrWhiteSpace();

        // The mock serves a signed JWT (header.payload.signature).
        // Decode the payload segment (index 1) to inspect the metadata statement content.
        var segments = blobJwt.Trim().Split('.');
        segments.Length.Should().Be(3, "MDS3 blob must be a valid 3-part signed JWT");

        var payloadJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(segments[1]);
        payloadJson.Should().Contain("Sentinel hermetic test authenticator",
            "MDS3 mock must be serving the expected blob JWT");

        var fetchesBefore = _fixture.Mds3FetchCount();
        _output.WriteLine($"MDS3 fetch count before test: {fetchesBefore}");

        // Act: Attempt registration with CDP virtual authenticator under direct policy
        await using var session = await _fixture.StartCeremonyAsync(WebAuthnAal3Fixture.Mds3RealmName);

        await WebAuthnAal3Fixture.CompleteLoginAsync(
            session,
            WebAuthnAal3Fixture.RogueUsername,
            WebAuthnAal3Fixture.TestPassword);

        // Click Register to trigger attestation submission
        await session.Page.WaitForSelectorAsync("#registerWebAuthn",
            new PageWaitForSelectorOptions { Timeout = 20000 });
        await session.Page.ClickAsync("#registerWebAuthn");

        // Wait for Keycloak to reject the attestation
        var errorPage = await WebAuthnAal3Fixture.WaitForRegistrationErrorAsync(session);

        // Assert: Fail-closed rejection
        errorPage.Should().Contain("invalid cert path",
            "Keycloak must reject untrusted attestation under direct policy");

        // Verify we never reached the callback (registration was blocked)
        session.Page.Url.Should().NotContain($"localhost:{_fixture.CallbackPort}",
            "Registration must not succeed — callback should never be reached");

        // Assert: MDS3 mock was NEVER queried (Keycloak uses truststore, not metadata)
        var fetchesAfter = _fixture.Mds3FetchCount();
        fetchesAfter.Should().Be(fetchesBefore,
            "Keycloak 26.6.4 has no MDS3 acquisition feature (keycloak/keycloak#9509); " +
            "attestation trust is anchored on the configured truststore, so the mock is never queried");

        _output.WriteLine($"✅ FR-10 verified: rogue authenticator rejected, MDS3 fetches unchanged ({fetchesBefore})");
    }
}