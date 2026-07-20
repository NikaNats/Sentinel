using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Sentinel.Tests.Shared;
using Xunit;

namespace Sentinel.Tests.DPoP;

public sealed class DpopProofValidatorTests : IDisposable
{
    private readonly IOptions<DPoPOptions> _dpopOptions;
    private readonly ECDsa _ecdsa;
    private readonly Dictionary<string, object> _publicJwk;
    private readonly StrictJtiReplayCache _replayCache;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly DpopThumbprintComputer _thumbprintComputer;
    private readonly FakeTimeProvider _timeProvider;
    private readonly DpopProofValidator _validator;

    public DpopProofValidatorTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "sentinel-test-01" };

        var parameters = _ecdsa.ExportParameters(false);
        _publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X ?? throw new InvalidOperationException()),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y ?? throw new InvalidOperationException())
        };

        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _replayCache = new StrictJtiReplayCache();
        _thumbprintComputer = new DpopThumbprintComputer();

        _dpopOptions = Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 60,
            AllowedClockSkewSeconds = 5,
            RequireNonce = false,
            AllowedAlgorithms = ["ES256", "ML-DSA-65"]
        });

        _validator = new DpopProofValidator(
            _replayCache,
            _dpopOptions,
            _thumbprintComputer,
            _timeProvider);
    }

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    public void Dispose() => _ecdsa?.Dispose();

    [Fact(DisplayName = "✅ Invariant: Perfectly signed and timed proof MUST authorize")]
    public async Task ValidateAsync_ValidProof_ReturnsSuccess()
    {
        const string requestUri = "https://sentinel.local/api/v1/vault";
        var proof = CreateSignedProof("POST", requestUri);

        _replayCache.ExpectSuccess();

        var request = new DpopValidationRequest(proof, "POST", new Uri(requestUri));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeTrue("A valid cryptographic proof is the primary token-binding requirement.");
        result.Value.Thumbprint.Should().NotBeNullOrEmpty("DPoP thumbprint must be computed for token binding.");
        _replayCache.Verify();
    }

    [Fact(DisplayName = "🛡️ Adversarial: Tampered signature MUST result in Fail-Closed")]
    public async Task ValidateAsync_TamperedSignature_ReturnsFailure()
    {
        var validProof = CreateSignedProof("GET", "https://api.io/t");
        var parts = validProof.Split('.');

        if (parts.Length != 3)
        {
            throw new InvalidOperationException("Invalid JWT structure");
        }

        var tamperedSignature = new string(parts[2].Reverse().ToArray());
        var tamperedProof = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

        var request = new DpopValidationRequest(tamperedProof, "GET", new Uri("https://api.io/t"));

        _replayCache.ExpectNoCalls();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse("Tampered signature must be rejected before any side effects.");
        result.ErrorMessage.Should().Be("invalid_signature");
        _replayCache.VerifyNoCalls();
    }

    [Theory(DisplayName = "⏱️ Boundary: Temporal window must be enforced to the millisecond")]
    [InlineData(-61, false, "Expired: 1ms past 60s window")]
    [InlineData(-60, true, "Boundary: Exactly 60s ago (at edge)")]
    [InlineData(-5, true, "Well within: 5 seconds ago")]
    [InlineData(0, true, "Current time")]
    [InlineData(5, true, "Boundary: Exactly 5s in future (at skew edge)")]
    [InlineData(6, false, "Future: 1ms past skew limit")]
    public async Task ValidateAsync_TemporalBoundaries_EnforceStrictWindow(
        int secondsOffset,
        bool expectedSuccess,
        string scenario)
    {
        var iat = _timeProvider.GetUtcNow().AddSeconds(secondsOffset);
        var proof = CreateSignedProof("GET", "https://api.io/t", iat: iat);

        if (expectedSuccess)
        {
            _replayCache.ExpectSuccess();
        }
        else
        {
            _replayCache.ExpectNoCalls();
        }

        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.io/t"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().Be(expectedSuccess, scenario);
    }

    [Fact(DisplayName = "⚠️ Fail-Closed: Infrastructure unavailability MUST deny access")]
    public async Task ValidateAsync_CacheOutage_ReturnsFailure()
    {
        var proof = CreateSignedProof("GET", "https://api.io/t");

        _replayCache.SetShouldFail();

        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.io/t"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse(
            "In security logic, ambiguity is a denial. " +
            "Never allow bypass if the cache is down (Fail-Closed principle).");
    }

    [Fact(DisplayName = "🛑 Cancellation: OperationCanceledException MUST propagate")]
    public async Task ValidateAsync_WhenCancellationRequested_ThrowsOperationCanceledException()
    {
        var proof = CreateSignedProof("GET", "https://api.io/t");

        var options = Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 60,
            AllowedClockSkewSeconds = 5,
            RequireNonce = false,
            AllowedAlgorithms = ["ES256"]
        });

        var validator = new DpopProofValidator(
            new CancellationAwareReplayCache(),
            options,
            _thumbprintComputer,
            _timeProvider);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.io/t"));

        var act = () => validator.ValidateAsync(request, cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "🎯 URI Binding: HTU (HTTP URI) mismatch MUST prevent cross-endpoint replay")]
    public async Task ValidateAsync_HtuMismatch_ReturnsFailure()
    {
        var proof = CreateSignedProof("POST", "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/admin"));

        _replayCache.ExpectNoCalls();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse("URI mismatch is a replay attack.");
        result.ErrorMessage.Should().Be("htu_mismatch");
        _replayCache.VerifyNoCalls();
    }

    [Fact(DisplayName = "🔐 JWK Header: Embedded public key MUST match actual signature")]
    public async Task ValidateAsync_TamperedJwkHeader_RejectsKeySwap()
    {
        using var tamperedEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tamperedParameters = tamperedEcdsa.ExportParameters(false);
        var wrongJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(tamperedParameters.Q.X ?? throw new InvalidOperationException()),
            ["y"] = Base64UrlEncoder.Encode(tamperedParameters.Q.Y ?? throw new InvalidOperationException())
        };

        var proof = TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256,
            wrongJwk,
            "POST",
            "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        _replayCache.ExpectNoCalls();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse("JWK swapping must be detected and rejected.");
        _replayCache.VerifyNoCalls();
    }

    [Fact(DisplayName = "🔄 JTI Replay: Duplicate proof MUST be rejected")]
    public async Task ValidateAsync_ReplayedJti_PreventsDuplicateUse()
    {
        var proof = CreateSignedProof("POST", "https://api.io/vault");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        _replayCache.ExpectSuccess();

        var firstResult = await _validator.ValidateAsync(request, TestCancellationToken);
        firstResult.IsSuccess.Should().BeTrue("First use of valid proof must pass");

        _replayCache.Reset();
        _replayCache.ExpectFalse();

        var replayResult = await _validator.ValidateAsync(request, TestCancellationToken);

        replayResult.IsSuccess.Should().BeFalse("Replayed JTIs must trigger a security rejection.");
    }

    [Fact(DisplayName = "🛡️ DoS: DPoP header exceeding 8KB max length limit MUST be rejected instantly")]
    public async Task ValidateAsync_HeaderExceedingMaxLength_ReturnsFailureInstantly()
    {
        var massiveHeader = new string('A', 8193); // Exceeds MaxDpopHeaderLength (8192)
        var request = new DpopValidationRequest(massiveHeader, "POST", new Uri("https://api.io/vault"));

        _replayCache.ExpectNoCalls();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("invalid_dpop_header_size",
            "Huge header sizes must be blocked at boundary to prevent DoS.");
        _replayCache.VerifyNoCalls();
    }

    [Fact(DisplayName = "🛡️ Safety: Null validation request object MUST return invalid_request")]
    public async Task ValidateAsync_NullRequestObject_ReturnsFailureSafely()
    {
        var result = await _validator.ValidateAsync(null!, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("invalid_request", "Null request parameter must fail-closed cleanly.");
    }

    [Theory(DisplayName = "🛡️ RSA Primes: Rejects JWKs containing private primes p and q")]
    [InlineData("p")]
    [InlineData("q")]
    public async Task ValidateAsync_JwkWithPrivatePrimes_FailsClosed(string leakProperty)
    {
        var tamperedJwk = new Dictionary<string, object>(_publicJwk);
        tamperedJwk[leakProperty] = Base64UrlEncoder.Encode(new byte[128]); // Inject raw private component

        var proof = TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256,
            tamperedJwk,
            "POST",
            "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("private_jwk_rejected", "JWK must not leak secret cryptographic material.");
    }

    [Fact(DisplayName = "🛡️ Symmetric Key: Rejects JWKs containing shared secret material 'k'")]
    public async Task ValidateAsync_JwkWithSymmetricKey_FailsClosed()
    {
        var tamperedJwk = new Dictionary<string, object>(_publicJwk);
        tamperedJwk["k"] = Base64UrlEncoder.Encode(new byte[32]); // Inject symmetric key material

        var proof = TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256,
            tamperedJwk,
            "POST",
            "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("private_jwk_rejected");
    }

    [Fact(DisplayName = "✅ Case-Sensitivity: Case-insensitive HTM matching (get vs GET) MUST succeed")]
    public async Task ValidateAsync_CaseInsensitiveHtm_Succeeds()
    {
        const string requestUri = "https://sentinel.local/api/v1/vault";
        var proof = CreateSignedProof("get", requestUri); // Lowercase get in token

        _replayCache.ExpectSuccess();

        var request = new DpopValidationRequest(proof, "GET", new Uri(requestUri)); // Uppercase GET in HTTP request

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeTrue("RFC 9449 recommends case-insensitive matching of HTTP method strings.");
    }

    [Fact(DisplayName = "✅ Port Normalization: Request matching default HTTPS port (443) on same domain MUST succeed")]
    public async Task ValidateAsync_DefaultPortNormalization_Succeeds()
    {
        var proof = CreateSignedProof("POST", "https://api.io/vault"); // No port in proof htu
        var request =
            new DpopValidationRequest(proof, "POST", new Uri("https://api.io:443/vault")); // Port 443 in request htu

        _replayCache.ExpectSuccess();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeTrue("Standard ports (443/80) must be normalized out of URIs before comparison.");
    }

    [Fact(DisplayName = "🛡️ PQC Size Validation: Rejects ML-DSA public key with invalid size to prevent DoS")]
    public async Task ValidateAsync_MlDsaKeyWithInvalidSize_ReturnsFailure()
    {
        var malformedMlDsaJwk = new Dictionary<string, object>
        {
            ["kty"] = "ML-DSA",
            ["x"] = Base64UrlEncoder.Encode(new byte[100]) // Invalid size (ML-DSA-65 expects 1952 bytes)
        };

        // Bypassing real signing to avoid NotSupportedException during test setup
        var header = new Dictionary<string, object>
        {
            ["alg"] = "ML-DSA-65",
            ["typ"] = "dpop+jwt",
            ["jwk"] = malformedMlDsaJwk
        };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = "POST",
            ["htu"] = "https://api.io/vault",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);
        var fakeJwtWithMalformedJwk =
            $"{Base64UrlEncoder.Encode(headerJson)}.{Base64UrlEncoder.Encode(payloadJson)}.fake_signature";

        var request = new DpopValidationRequest(fakeJwtWithMalformedJwk, "POST", new Uri("https://api.io/vault"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should()
            .Be("invalid_jwk", "Malformed PQC key sizes must be caught before native validation.");
    }

    [Fact(DisplayName = "🛡️ RFC 9449: Rejects JWK 'alg' mismatched with JWT 'alg'")]
    public async Task ValidateAsync_JwkAlgMismatchedWithTokenAlg_ReturnsFailure()
    {
        var tamperedJwk = new Dictionary<string, object>(_publicJwk);
        tamperedJwk["alg"] = "PS256"; // Mismatched: Token is ES256, but JWK claim claims PS256

        var proof = TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256, // Token alg: ES256
            tamperedJwk,
            "POST",
            "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("unsupported_algorithm");
    }

    [Fact(DisplayName = "🎯 URI Validation: Malformed absolute htu MUST prevent bypass and return htu_mismatch")]
    public async Task ValidateAsync_MalformedHtu_ReturnsFailure()
    {
        // Generate signed token with custom malformed HTU to bypass CreateValidProof's URI check
        var proof = CreateSignedProofWithCustomHtu("invalid-uri-without-scheme");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("htu_mismatch",
            "Malformed URIs must fail-closed rather than allowing empty matches.");
    }

    [Fact(DisplayName = "🔐 Nonce 1: RequireNonce=True and no nonce in proof MUST result in use_dpop_nonce")]
    public async Task ValidateAsync_RequireNonceTrue_NoNonceInProof_Fails()
    {
        _dpopOptions.Value.RequireNonce = true;
        var proof = CreateSignedProof("POST", "https://api.io/vault", null);
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"),
            expectedNonce: "server-nonce-123");

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("use_dpop_nonce");
    }

    [Fact(DisplayName =
        "🔐 Nonce 2: RequireNonce=True and empty/expired ExpectedNonce on server MUST result in use_dpop_nonce")]
    public async Task ValidateAsync_RequireNonceTrue_NoExpectedNonceOnServer_Fails()
    {
        _dpopOptions.Value.RequireNonce = true;
        var proof = CreateSignedProof("POST", "https://api.io/vault", "client-nonce-xyz");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"), expectedNonce: null);

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("use_dpop_nonce");
    }

    [Fact(DisplayName = "🔐 Nonce 3: RequireNonce=True and mismatched nonce MUST result in use_dpop_nonce")]
    public async Task ValidateAsync_RequireNonceTrue_MismatchedNonce_Fails()
    {
        _dpopOptions.Value.RequireNonce = true;
        var proof = CreateSignedProof("POST", "https://api.io/vault", "wrong-nonce-abc");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"),
            expectedNonce: "correct-nonce-xyz");

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("use_dpop_nonce");
    }

    [Fact(DisplayName = "🔐 Nonce 4: RequireNonce=True and valid matching nonce MUST succeed")]
    public async Task ValidateAsync_RequireNonceTrue_ValidMatchingNonce_Succeeds()
    {
        _dpopOptions.Value.RequireNonce = true;
        const string matchingNonce = "matching-nonce-12345";
        var proof = CreateSignedProof("POST", "https://api.io/vault", matchingNonce);
        var request =
            new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"), expectedNonce: matchingNonce);

        _replayCache.ExpectSuccess();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact(DisplayName = "🔐 Nonce 5: RequireNonce=False and expected nonce active but missing in proof MUST fail")]
    public async Task ValidateAsync_RequireNonceFalse_ExpectedActiveButMissingInProof_Fails()
    {
        _dpopOptions.Value.RequireNonce = false;
        var proof = CreateSignedProof("POST", "https://api.io/vault", null);
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"),
            expectedNonce: "active-server-nonce");

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("use_dpop_nonce");
    }

    [Fact(DisplayName =
        "🔐 Nonce 6: RequireNonce=False and no active expected nonce on server MUST allow proof without nonce")]
    public async Task ValidateAsync_RequireNonceFalse_NoExpectedNonce_SucceedsWithoutNonceInProof()
    {
        _dpopOptions.Value.RequireNonce = false;
        var proof = CreateSignedProof("POST", "https://api.io/vault", null);
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"), expectedNonce: null);

        _replayCache.ExpectSuccess();

        var result = await _validator.ValidateAsync(request, TestCancellationToken);

        result.IsSuccess.Should().BeTrue();
    }

    private string CreateSignedProof(
        string method,
        string uri,
        string? nonce = null,
        DateTimeOffset? iat = null) =>
        TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256,
            _publicJwk,
            method,
            uri,
            nonce,
            iat);

    private string CreateSignedProofWithCustomHtu(string malformedHtu)
    {
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "POST",
                ["htu"] = malformedHtu, // Directly injected bypassing uri format checks in helper
                ["iat"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = _publicJwk
            }
        };
        return handler.CreateToken(descriptor);
    }

    private sealed class StrictJtiReplayCache : IJtiReplayCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _usedJtis = new();
        private bool _callHappened;
        private bool _expectCalls = true;
        private int _expectedReturnValue = 1;
        private bool _shouldFail;

        public async Task<bool> TryMarkUsedAsync(
            string jti,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            _callHappened = true;

            if (!_expectCalls)
            {
                throw new InvalidOperationException("Cache was called when it should not have been");
            }

            if (_shouldFail)
            {
                _shouldFail = false;
                throw new InvalidOperationException("Cache operation failed");
            }

            if (_expectedReturnValue == 1)
            {
                return await Task.FromResult(_usedJtis.TryAdd(jti, expiresAt));
            }

            if (_expectedReturnValue == 0)
            {
                return await Task.FromResult(false);
            }

            throw new InvalidOperationException("Invalid expected return value");
        }

        public async Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
        {
            var now = DateTimeOffset.UtcNow;
            var expiredJtis = _usedJtis
                .Where(kvp => kvp.Value <= now)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var jti in expiredJtis)
            {
                _usedJtis.TryRemove(jti, out _);
            }

            await Task.CompletedTask;
        }

        public void ExpectSuccess()
        {
            _expectCalls = true;
            _expectedReturnValue = 1;
            _callHappened = false;
        }

        public void ExpectFalse()
        {
            _expectCalls = true;
            _expectedReturnValue = 0;
            _callHappened = false;
        }

        public void ExpectNoCalls()
        {
            _expectCalls = false;
            _expectedReturnValue = -1;
            _callHappened = false;
        }

        public void Verify()
        {
            if (_expectCalls && !_callHappened)
            {
                throw new InvalidOperationException("Expected cache call did not happen");
            }
        }

        public void VerifyNoCalls()
        {
            if (_callHappened)
            {
                throw new InvalidOperationException("Unexpected cache call occurred");
            }
        }

        public void Reset()
        {
            _usedJtis.Clear();
            _callHappened = false;
        }

        public void SetShouldFail() => _shouldFail = true;
    }

    private sealed class CancellationAwareReplayCache : IJtiReplayCache
    {
        public Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(true);
        }

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
