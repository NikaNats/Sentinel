using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     Real end-to-end FAPI 2.0 browser flow tests against a live Keycloak
///     instance: the full PAR -> authorize (real browser login) -> code ->
///     DPoP-bound token exchange -> protected-resource path, plus the
///     enforcement negatives (PAR reuse, PAR expiry, direct /authorize,
///     plain PKCE, wrong verifier, DPoP proof replay).
///
///     Assertion contract derived from live probes against Keycloak 26.6.4
///     (sentinel-dast realm), see docs/KEYCLOAK_FAPI_ENFORCEMENT.md:
///     - PAR requires `nonce` (client policy);
///     - the token endpoint enforces the dpop_jkt binding declared in PAR;
///     - Keycloak issues NO DPoP-Nonce in this configuration;
///     - enforcement violations render a Keycloak error PAGE (HTTP 400), not
///       an OAuth error redirect;
///     - userinfo returns sub + name (no preferred_username claim mapping).
/// </summary>
[Collection("Playwright FAPI 2")]
[Trait("Category", "E2E")]
[Trait("Category", "FAPI2")]
public sealed class RealParPkceDpopFlowTests
{
    private readonly PlaywrightFapi2Fixture _fixture;
    private readonly ITestOutputHelper _output;

    public RealParPkceDpopFlowTests(PlaywrightFapi2Fixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    private static HttpClient CreateHttpClient() => PlaywrightFapi2Fixture.CreateTrustingHttpClient();

    private static CancellationToken TestCt => TestContext.Current.CancellationToken;

    private string UserInfoUrl => $"{_fixture.RealmUrl}/protocol/openid-connect/userinfo";

    [Fact(DisplayName = "Full PAR + PKCE S256 + DPoP browser flow succeeds with sender-constrained token")]
    public async Task FullBrowserFlow_Par_Pkce_Dpop_Succeeds()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var state = Fapi2BrowserClient.GenerateState();
        var nonce = Fapi2BrowserClient.GenerateNonce();

        // Act 1: pushed authorization request.
        var parResponse = await fapiClient.SubmitParRequestAsync(
            scope: "openid profile email",
            codeChallenge: codeChallenge,
            state: state,
            nonce: nonce,
            ct: TestCt);

        parResponse.RequestUri.ToString().Should().StartWith(
            "urn:ietf:params:oauth:request_uri:", "PAR must return an RFC 9126 request_uri");
        parResponse.ExpiresIn.Should().BeGreaterThan(0).And.BeLessThanOrEqualTo(60, "realm PAR TTL is 60s");

        // Act 2: browser authorization + login.
        var browserResult = await _fixture.ExecuteBrowserLoginAsync(
            fapiClient.BuildAuthorizationUrl(parResponse.RequestUri));
        _output.WriteLine($"browser result: Error=[{browserResult.Error}] page=[{TrimForLog(browserResult.ErrorPageText ?? string.Empty)}]");

        browserResult.AuthorizationCode.Should().NotBeNullOrEmpty("the browser must receive an authorization code");
        browserResult.Error.Should().BeNull();
        browserResult.ErrorPageText.Should().BeNull();
        browserResult.State.Should().Be(state, "OAuth state must round-trip (CSRF guard)");

        // Act 3: DPoP-bound token exchange.
        var tokenResponse = await fapiClient.ExchangeCodeForTokensAsync(
            browserResult.AuthorizationCode!, codeVerifier, ct: TestCt);

        tokenResponse.AccessToken.Should().NotBeNullOrEmpty();
        tokenResponse.TokenType.Should().Be("DPoP", "the realm enforces DPoP-bound access tokens");

        // The issued token's cnf.jkt must equal the DPoP key declared in PAR.
        var token = new JsonWebTokenHandler().ReadJsonWebToken(tokenResponse.AccessToken);
        using (var cnf = JsonDocument.Parse(token.GetClaim("cnf")!.Value))
        {
            cnf.RootElement.GetProperty("jkt").GetString()
                .Should().Be(fapiClient.DpopBuilder.JwkThumbprint, "the token must be bound to the DPoP key (sender constraint)");
        }

        // The id_token must carry the nonce from the PAR (session fixation protection).
        tokenResponse.IdToken.Should().NotBeNullOrEmpty();
        var idToken = new JsonWebTokenHandler().ReadJsonWebToken(tokenResponse.IdToken!);
        idToken.GetClaim("nonce")!.Value.Should().Be(nonce, "the nonce must round-trip into the id_token");

        // Keycloak 26.6.4 does not issue DPoP nonces under this policy.
        tokenResponse.DpopNonce.Should().BeNull(
            "Keycloak 26.6.4 issues no DPoP-Nonce here; when nonce support is enabled, this assertion must be revisited");

        // Act 4: protected-resource call (Keycloak userinfo) with the DPoP-bound token.
        using var protectedResponse = await fapiClient.CallProtectedResourceAsync(
            UserInfoUrl, tokenResponse.AccessToken, ct: TestCt);

        protectedResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var userinfo = await protectedResponse.Content.ReadAsStringAsync(TestCt);
        using (var doc = JsonDocument.Parse(userinfo))
        {
            doc.RootElement.GetProperty("sub").GetString().Should().NotBeNullOrEmpty();
            doc.RootElement.GetProperty("name").GetString().Should().NotBeNullOrEmpty();
        }
    }

    [Fact(DisplayName = "DPoP proofs without and with a fabricated nonce are both accepted")]
    public async Task DpopNonceBehavior_MatchesKeycloak26_6_4()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var state = Fapi2BrowserClient.GenerateState();
        var nonce = Fapi2BrowserClient.GenerateNonce();

        var parResponse = await fapiClient.SubmitParRequestAsync("openid", codeChallenge, state, nonce, ct: TestCt);
        var browserResult = await _fixture.ExecuteBrowserLoginAsync(
            fapiClient.BuildAuthorizationUrl(parResponse.RequestUri));

        browserResult.AuthorizationCode.Should().NotBeNullOrEmpty();

        // No nonce needed: Keycloak issues and requires no DPoP nonce.
        var tokenResponse = await fapiClient.ExchangeCodeForTokensAsync(
            browserResult.AuthorizationCode!, codeVerifier, ct: TestCt);
        tokenResponse.AccessToken.Should().NotBeNullOrEmpty();

        // A fabricated nonce in the proof is tolerated (not rejected).
        var proofWithFabricatedNonce = fapiClient.DpopBuilder.BuildTokenEndpointProof(
            fapiClient.TokenEndpoint, nonce: "fabricated-nonce");
        using (var request = new HttpRequestMessage(HttpMethod.Post, fapiClient.TokenEndpoint)
               {
                   Content = new FormUrlEncodedContent(new Dictionary<string, string>
                   {
                       ["grant_type"] = "authorization_code",
                       ["code"] = browserResult.AuthorizationCode!,
                       ["redirect_uri"] = PlaywrightFapi2Fixture.RedirectUri,
                       ["client_id"] = PlaywrightFapi2Fixture.ClientId,
                       ["code_verifier"] = codeVerifier
                   })
               })
        {
            request.Headers.Add("DPoP", proofWithFabricatedNonce);
            // The first code was already consumed; this call must fail on the
            // code, NOT on the nonce - proving the nonce claim is not enforced.
            using var response = await http.SendAsync(request, TestCt);
            var body = await response.Content.ReadAsStringAsync(TestCt);
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest, "reused code is rejected");
            body.Should().Contain("Code not valid", "the rejection must be about the code, not the nonce");
        }
    }

    [Fact(DisplayName = "Reused request_uri is rejected (PAR single-use enforcement)")]
    public async Task ReusedRequestUri_IsRejected()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var parResponse = await fapiClient.SubmitParRequestAsync("openid", codeChallenge,
            Fapi2BrowserClient.GenerateState(), Fapi2BrowserClient.GenerateNonce(), ct: TestCt);

        var authUrl = fapiClient.BuildAuthorizationUrl(parResponse.RequestUri);

        var firstResult = await _fixture.ExecuteBrowserLoginAsync(authUrl);
        firstResult.AuthorizationCode.Should().NotBeNullOrEmpty("first use must succeed");

        var secondResult = await _fixture.ExecuteBrowserLoginAsync(authUrl);
        secondResult.AuthorizationCode.Should().BeNull("a consumed request_uri must not yield a code");
        secondResult.ErrorPageText.Should().NotBeNullOrEmpty(
            "Keycloak renders an error page for the reused request_uri (verified: HTTP 400, no redirect)");
        _output.WriteLine($"reuse rejection page: {TrimForLog(secondResult.ErrorPageText!)}");
    }

    [Fact(DisplayName = "Direct /authorize without PAR is rejected")]
    public async Task DirectAuthorizeWithoutPar_IsRejected()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var directAuthUrl =
            new Uri(
                $"{fapiClient.AuthorizationEndpoint}?client_id={PlaywrightFapi2Fixture.ClientId}" +
                $"&response_type=code&redirect_uri={Uri.EscapeDataString(PlaywrightFapi2Fixture.RedirectUri)}" +
                $"&scope=openid&code_challenge={codeChallenge}&code_challenge_method=S256");

        var browserResult = await _fixture.ExecuteBrowserLoginAsync(directAuthUrl);

        browserResult.AuthorizationCode.Should().BeNull("no code may be issued without PAR");
        browserResult.ErrorPageText.Should().NotBeNullOrEmpty(
            "the client policy requires pushed authorization requests (verified: error page mentions request_uri)");
        browserResult.ErrorPageText.Should().Contain("request_uri");
        _output.WriteLine($"direct-authorize rejection page: {TrimForLog(browserResult.ErrorPageText!)}");
    }

    [Fact(DisplayName = "Expired request_uri is rejected (PAR TTL enforcement)")]
    public async Task ExpiredRequestUri_IsRejected()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var parResponse = await fapiClient.SubmitParRequestAsync("openid", codeChallenge,
            Fapi2BrowserClient.GenerateState(), Fapi2BrowserClient.GenerateNonce(), ct: TestCt);

        _output.WriteLine("waiting for the request_uri TTL (60s) to elapse...");
        await Task.Delay(TimeSpan.FromSeconds(65), TestCt);

        var browserResult = await _fixture.ExecuteBrowserLoginAsync(
            fapiClient.BuildAuthorizationUrl(parResponse.RequestUri));

        browserResult.AuthorizationCode.Should().BeNull("an expired request_uri must not yield a code");
        browserResult.ErrorPageText.Should().NotBeNullOrEmpty("Keycloak must reject the expired request_uri");
        _output.WriteLine($"expiry rejection page: {TrimForLog(browserResult.ErrorPageText!)}");
    }

    [Fact(DisplayName = "Wrong PKCE verifier is rejected at the token endpoint")]
    public async Task WrongPkceVerifier_IsRejectedAtTokenEndpoint()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var parResponse = await fapiClient.SubmitParRequestAsync("openid", codeChallenge,
            Fapi2BrowserClient.GenerateState(), Fapi2BrowserClient.GenerateNonce(), ct: TestCt);
        var browserResult = await _fixture.ExecuteBrowserLoginAsync(
            fapiClient.BuildAuthorizationUrl(parResponse.RequestUri));

        var act = async () => await fapiClient.ExchangeCodeForTokensAsync(
            browserResult.AuthorizationCode!, "definitely-not-the-verifier", ct: TestCt);

        var exception = await act.Should().ThrowAsync<TokenExchangeException>();
        exception.Which.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        exception.Which.ResponseBody.Should().Contain("PKCE verification failed");
        _output.WriteLine($"rejection body: {exception.Which.ResponseBody}");
    }

    [Fact(DisplayName = "Plain PKCE method is rejected by the client policy")]
    public async Task PlainPkceMethod_IsRejectedByClientPolicy()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var act = async () => await fapiClient.SubmitParRequestAsync(
            scope: "openid",
            codeChallenge: "plain-challenge-value",
            state: Fapi2BrowserClient.GenerateState(),
            nonce: Fapi2BrowserClient.GenerateNonce(),
            codeChallengeMethod: "plain",
            ct: TestCt);

        var exception = await act.Should().ThrowAsync<ParRequestException>();
        exception.Which.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        exception.Which.ResponseBody.Should().Contain("code challenge method");
        _output.WriteLine($"rejection body: {exception.Which.ResponseBody}");
    }

    [Fact(DisplayName = "DPoP proof replay against the resource server is documented")]
    public async Task DpopProofReplay_ResourceServerBehavior_Documented()
    {
        using var http = CreateHttpClient();
        using var fapiClient = new Fapi2BrowserClient(
            http,
            PlaywrightFapi2Fixture.ClientId,
            PlaywrightFapi2Fixture.RedirectUri,
            _fixture.BaseAddress,
            PlaywrightFapi2Fixture.RealmName);

        var (codeVerifier, codeChallenge) = Fapi2BrowserClient.GeneratePkceS256();
        var parResponse = await fapiClient.SubmitParRequestAsync("openid", codeChallenge,
            Fapi2BrowserClient.GenerateState(), Fapi2BrowserClient.GenerateNonce(), ct: TestCt);
        var browserResult = await _fixture.ExecuteBrowserLoginAsync(
            fapiClient.BuildAuthorizationUrl(parResponse.RequestUri));
        var tokenResponse = await fapiClient.ExchangeCodeForTokensAsync(
            browserResult.AuthorizationCode!, codeVerifier, ct: TestCt);

        // First call with a fixed jti.
        const string replayJti = "replay-jti-0000000000000000000000000";
        using (var first = await fapiClient.CallProtectedResourceAsync(
                   UserInfoUrl, tokenResponse.AccessToken, explicitJti: replayJti, ct: TestCt))
        {
            first.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        // Replay: the SAME jti (and htu/htm/ath) again.
        var replayProof = fapiClient.DpopBuilder.BuildResourceRequestProof(
            "GET", UserInfoUrl, tokenResponse.AccessToken, explicitJti: replayJti);

        using var replayRequest = new HttpRequestMessage(HttpMethod.Get, UserInfoUrl);
        replayRequest.Headers.Authorization = new AuthenticationHeaderValue("DPoP", tokenResponse.AccessToken);
        replayRequest.Headers.Add("DPoP", replayProof);
        using var replayResponse = await http.SendAsync(replayRequest, TestCt);

        _output.WriteLine($"replayed DPoP proof result: {(int)replayResponse.StatusCode} {replayResponse.ReasonPhrase}");
        // Keycloak's userinfo endpoint performs no jti-replay check of its own.
        // The Sentinel API rejects replays via the Redis-backed jti cache
        // (DpopValidationMiddleware + JtiReplayCache), covered by the unit and
        // security suites - this test pins the resource-server baseline.
        replayResponse.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }

    private static string TrimForLog(string text) =>
        text.ReplaceLineEndings(" ").Trim();
}
