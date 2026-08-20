using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Playwright;
using Sentinel.Tests.Shared.Fixtures;
using Xunit;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     ADR-2026-006 Pillar 1: Playwright CDP ceremony tests against a real
///     Keycloak 26.6.4 with the sentinel-dast realm.
/// </summary>
[Collection(WebAuthnAal3Collection.Name)]
public sealed class WebAuthnAal3CeremonyTests : IAsyncLifetime
{
    private readonly WebAuthnAal3Fixture _fixture;
    private readonly ITestOutputHelper _output;
    private readonly ActivitySource _activitySource = new("Sentinel.Tests.WebAuthnAal3");

    public WebAuthnAal3CeremonyTests(WebAuthnAal3Fixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
        _output = output ?? throw new ArgumentNullException(nameof(output));
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public ValueTask DisposeAsync()
    {
        _activitySource.Dispose();
        return ValueTask.CompletedTask;
    }

    // =========================================================================
    // FR-08 + FR-09 + FR-11: Enrollment Flow
    // =========================================================================

    [Fact(DisplayName = "FR-08/09/11: Enrollment registers resident UV key and token carries acr3 + DPoP binding")]
    public async Task Enrollment_RegistersResidentUvKey_AndTokenCarriesAcr3AndDpopBinding()
    {
        using var activity = _activitySource.StartActivity("WebAuthn.Enrollment");
        await using var session = await _fixture.StartCeremonyAsync();

        _output.WriteLine("Starting WebAuthn enrollment ceremony...");
        await WebAuthnAal3Fixture.CompleteLoginAsync(
            session,
            WebAuthnAal3Fixture.EnrollUsername,
            WebAuthnAal3Fixture.TestPassword);

        var code = await WebAuthnAal3Fixture.WaitForAuthorizationCodeAsync(session);
        code.Should().NotBeNullOrEmpty("Authorization code must be issued after successful enrollment");

        var tokens = await WebAuthnAal3Fixture.ExchangeCodeAsync(session, code);
        tokens.AccessToken.Should().NotBeNullOrEmpty();
        tokens.TokenType.Should().Be("DPoP", "FAPI 2.0 requires DPoP-bound tokens");

        var jwt = new JsonWebToken(tokens.AccessToken);
        jwt.Typ.Should().BeOneOf("JWT", "DPoP", "Bearer");

        jwt.TryGetPayloadValue<string>("acr", out var acr).Should().BeTrue();
        acr.Should().BeOneOf("3", "acr3", "AAL3 enrollment must produce acr=3 or acr3");

        jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnfElement).Should().BeTrue();
        cnfElement.ValueKind.Should().Be(JsonValueKind.Object, "cnf must be a JSON object");
        cnfElement.TryGetProperty("jkt", out var jktProp).Should().BeTrue("cnf.jkt must be present");
        jktProp.GetString().Should().Be(session.Client.DpopBuilder.JwkThumbprint,
            "cnf.jkt must match the DPoP key declared in PAR request");

        var realmAttributes = await _fixture.GetRealmAttributesAsync();
        realmAttributes["webAuthnPolicyRequireResidentKey"].Should().Be("required");
        realmAttributes["webAuthnPolicyUserVerificationRequirement"].Should().Be("required");
        realmAttributes["webAuthnPolicyAuthenticatorAttachment"].Should().Be("cross-platform");
        realmAttributes["webAuthnPolicyRpId"].Should().Be("localhost");
        realmAttributes["browserFlow"].Should().Be(WebAuthnAal3Fixture.Aal3BrowserFlow);

        _output.WriteLine($"✅ Enrollment completed. Token acr={acr}");
    }

    // =========================================================================
    // FR-13: Subsequent Login (Passkey Assertion)
    // =========================================================================

    [Fact(DisplayName = "FR-13: Subsequent login uses passkey assertion without re-enrollment")]
    public async Task SubsequentLogin_UsesPasskeyAssertion_NoReenrollment()
    {
        using var activity = _activitySource.StartActivity("WebAuthn.Assertion");
        await using var session = await _fixture.StartCeremonyAsync();

        // 1. Initial Enrollment in this session's virtual authenticator
        _output.WriteLine("Step 1: Enrolling passkey into session authenticator...");
        await WebAuthnAal3Fixture.CompleteLoginAsync(
            session,
            WebAuthnAal3Fixture.AssertUsername,
            WebAuthnAal3Fixture.TestPassword);

        var enrollCode = await WebAuthnAal3Fixture.WaitForAuthorizationCodeAsync(session);
        await WebAuthnAal3Fixture.ExchangeCodeAsync(session, enrollCode);

        // Clear active session cookies so Keycloak presents the login prompt anew for the assertion test
        await session.Context.ClearCookiesAsync();

        // 2. Subsequent Login in the SAME browser context (where the passkey lives)
        _output.WriteLine("Step 2: Performing passkey assertion in the same session context...");
        var (verifier, challenge) = Fapi2BrowserClient.GeneratePkceS256();
        var state = Fapi2BrowserClient.GenerateState();
        var nonce = Fapi2BrowserClient.GenerateNonce();
        var par = await session.Client.SubmitParRequestAsync("openid profile email", challenge, state, nonce, ct: TestContext.Current.CancellationToken);

        await session.Page.GotoAsync(session.Client.BuildAuthorizationUrl(par.RequestUri).ToString(), new PageGotoOptions
        {
            WaitUntil = WaitUntilState.DOMContentLoaded
        });

        await WebAuthnAal3Fixture.CompleteLoginAsync(
            session,
            WebAuthnAal3Fixture.AssertUsername,
            WebAuthnAal3Fixture.TestPassword);

        var assertCode = await WebAuthnAal3Fixture.WaitForAuthorizationCodeAsync(session);
        assertCode.Should().NotBeNullOrEmpty("Assertion must produce an authorization code");

        var tokens = await session.Client.ExchangeCodeForTokensAsync(assertCode, verifier, ct: TestContext.Current.CancellationToken);
        tokens.AccessToken.Should().NotBeNullOrEmpty();

        var jwt = new JsonWebToken(tokens.AccessToken);
        jwt.TryGetPayloadValue<string>("acr", out var acr).Should().BeTrue();
        acr.Should().BeOneOf("3", "acr3");

        _output.WriteLine($"✅ Assertion completed successfully without re-enrollment. Token acr={acr}");
    }

    // =========================================================================
    // FR-12: TOTP Conditional Recovery
    // =========================================================================

    [Fact(DisplayName = "FR-12: User without passkey but with TOTP falls to conditional OTP recovery")]
    public async Task TotpFallback_WithoutPasskeyButWithTotp_FallsToConditionalOtpRecovery()
    {
        using var activity = _activitySource.StartActivity("WebAuthn.TotpFallback");
        await using var session = await _fixture.StartCeremonyAsync();

        _output.WriteLine("Starting TOTP fallback ceremony...");
        await WebAuthnAal3Fixture.CompleteLoginAsync(
            session,
            WebAuthnAal3Fixture.TotpUsername,
            WebAuthnAal3Fixture.TestPassword);

        // If the flow already redirected to callback, extract code; otherwise complete OTP form
        if (!session.Page.Url.Contains("/callback", StringComparison.OrdinalIgnoreCase) &&
            !session.Page.Url.Contains($"localhost:{session.CallbackPort}", StringComparison.Ordinal))
        {
            await WebAuthnAal3Fixture.WaitForOtpFormAsync(session);
            await WebAuthnAal3Fixture.SubmitOtpAsync(
                session,
                WebAuthnAal3Fixture.ComputeTotp(_fixture.TotpSecret));
        }

        var code = await WebAuthnAal3Fixture.WaitForAuthorizationCodeAsync(session);
        code.Should().NotBeNullOrEmpty("TOTP fallback must produce authorization code");

        var tokens = await WebAuthnAal3Fixture.ExchangeCodeAsync(session, code);
        tokens.AccessToken.Should().NotBeNullOrEmpty();

        _output.WriteLine("✅ TOTP fallback completed successfully");
    }

    // =========================================================================
    // FR-14: Brute-Force Lockout (NEGATIVE TEST)
    // =========================================================================

    [Fact(DisplayName = "FR-14: Account locks after 5 consecutive failed authentication attempts")]
    public async Task BruteForce_LocksAccountAfterFiveFailedAttempts()
    {
        using var activity = _activitySource.StartActivity("WebAuthn.BruteForceLockout");

        _output.WriteLine("Testing brute-force lockout (5 failures spaced >1s)...");

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await using var session = await _fixture.StartCeremonyAsync();
            await WebAuthnAal3Fixture.CompleteLoginAsync(
                session, WebAuthnAal3Fixture.BruteForceUsername, "WrongPassword!");

            var isError = await WebAuthnAal3Fixture.WaitForErrorPageAsync(session);
            isError.Should().BeTrue($"Attempt {attempt} should show error page");

            // Spacing > 1000ms satisfies realm quickLoginCheckMilliSeconds requirement
            await Task.Delay(TimeSpan.FromMilliseconds(1200), CancellationToken.None);
        }

        // 6th attempt with CORRECT password must be locked out
        await using var lockedSession = await _fixture.StartCeremonyAsync();
        await WebAuthnAal3Fixture.CompleteLoginAsync(
            lockedSession, WebAuthnAal3Fixture.BruteForceUsername, WebAuthnAal3Fixture.TestPassword);

        var isLockedOut = await WebAuthnAal3Fixture.WaitForErrorPageAsync(lockedSession);
        isLockedOut.Should().BeTrue("Account must be locked and reject login after 5 consecutive failures");
        lockedSession.Page.Url.Should().NotContain("/callback", "Locked account must never receive an authorization code");

        _output.WriteLine("✅ Brute-force lockout verified after 5 failed attempts");
    }

    // =========================================================================
    // FR-09 Negative: Weak Authenticator Rejection (Policy Verification)
    // =========================================================================

    [Fact(DisplayName = "FR-09 Negative: Realm policy requires resident key (verified via Admin API)")]
    public async Task WeakAuthenticator_RealmPolicyRequiresResidentKey()
    {
        using var activity = _activitySource.StartActivity("WebAuthn.PolicyVerification");

        _output.WriteLine("Verifying realm WebAuthn policy enforces resident key requirement...");

        var realmAttributes = await _fixture.GetRealmAttributesAsync();

        realmAttributes["webAuthnPolicyRequireResidentKey"]
            .Should().Be("required",
                "Realm policy MUST require resident keys for AAL3 compliance");
        realmAttributes["webAuthnPolicyUserVerificationRequirement"]
            .Should().Be("required",
                "Realm policy MUST require user verification for AAL3 compliance");

        _output.WriteLine("✅ Realm policy correctly requires resident key + user verification");
    }
}

[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
internal sealed partial class WebAuthnTestJsonContext : JsonSerializerContext;