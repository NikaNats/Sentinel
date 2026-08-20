using System.Net;
using System.Text.Json;
using FluentAssertions;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     ADR-2026-006 Pillar 3 (FR-14): Brute-force protection against token endpoint.
///     The realm sets bruteForceProtected=true, failureFactor=5. Five consecutive failed
///     password-grant attempts lock the account: the 6th attempt with the CORRECT password
///     is rejected by Keycloak (invalid_grant).
/// </summary>
[Collection(WebAuthnAal3Collection.Name)]
public sealed class WebAuthnBruteForceTests(WebAuthnAal3Fixture fixture)
{
    [Fact]
    public async Task PasswordGrant_FiveFailures_DisablesAccount_EvenWithCorrectPassword()
    {
        using var http = WebAuthnAal3Fixture.CreateTrustingHttpClient();
        using var client = fixture.CreateFapiClient();

        // 1. Five consecutive failed attempts with wrong passwords
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var request = BuildPasswordGrant(client, $"WrongPassword{attempt}");
            using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            JsonDocument.Parse(body).RootElement.GetProperty("error").GetString()
                .Should().Be("invalid_grant");

            // Spacing must exceed quickLoginCheckMilliSeconds (1000ms)
            await Task.Delay(1200, TestContext.Current.CancellationToken);
        }

        // 2. The 6th attempt with the CORRECT password must still be rejected (account locked)
        using var sixth = BuildPasswordGrant(client, WebAuthnAal3Fixture.TestPassword);
        using var locked = await http.SendAsync(sixth, TestContext.Current.CancellationToken);
        var lockedBody = await locked.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        locked.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "Keycloak must refuse authentication for locked accounts even with the correct password.");

        var error = JsonDocument.Parse(lockedBody).RootElement;
        error.GetProperty("error").GetString().Should().Be("invalid_grant",
            "Locked account must be rejected with invalid_grant.");
    }

    private static HttpRequestMessage BuildPasswordGrant(Fapi2BrowserClient client, string password)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, client.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = WebAuthnAal3Fixture.Aal3ClientId,
                ["username"] = WebAuthnAal3Fixture.LockoutUsername,
                ["password"] = password
            })
        };

        // Fresh jti per attempt: DPoP replay protection rejects reused proofs.
        request.Headers.Add("DPoP", client.DpopBuilder.BuildTokenEndpointProof(
            client.TokenEndpoint, explicitJti: Guid.NewGuid().ToString("N")));
        return request;
    }
}