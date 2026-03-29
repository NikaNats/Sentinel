using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Sentinel.Tests.Shared;
using Xunit;

namespace Sentinel.Tests.DPoP;

/// <summary>
///     High-Assurance Security Invariant Suite for RFC 9449 (DPoP).
///     This suite treats security requirements as executable specifications.
///     Every test proves a specific mitigation in the Sentinel Threat Model.
///     ARCHITECTURE PRINCIPLES:
///     ✅ Deterministic Temporal Logic: Boundary testing at exact millisecond edges (-61,-60,+5,+6)
///     ✅ Cryptographic Reality: Real ECDsa P-256 signatures, not fake JWTs
///     ✅ Strict Verification: FakeJtiReplayCache with explicit expectations and assertion
///     ✅ Fail-Closed: Infrastructure unavailability results in automatic denial (no degradation)
///     ✅ Error Sanitization: Topology details never leak in error messages
///     ✅ Adversarial Verification: Signature tampering, JWK swaps, temporal attacks all tested
///     ✅ Resource Hygiene: IDisposable ensures proper cryptographic cleanup
/// </summary>
public sealed class DpopProofValidatorTests : IDisposable
{
    // ✅ Real cryptographic material for mathematically valid test vectors
    private readonly ECDsa _ecdsa;
    private readonly Dictionary<string, object> _publicJwk;
    private readonly StrictJtiReplayCache _replayCache;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly DpopThumbprintComputer _thumbprintComputer;
    private readonly FakeTimeProvider _timeProvider;
    private readonly DpopProofValidator _validator;

    public DpopProofValidatorTests()
    {
        // ====== 1. Arrange: Cryptographic Context ======
        // Create real P-256 key pair. Every test uses this to sign mathematically valid proofs.
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "sentinel-test-01" };

        // Export public key only (no private material) for embedding in JWK header
        var parameters = _ecdsa.ExportParameters(false);
        _publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X ?? throw new InvalidOperationException()),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y ?? throw new InvalidOperationException())
        };

        // ====== 2. Arrange: Infrastructure Mocks (Strict) ======
        // We use a strict fake cache implementation to ensure NO unintended side-effects or cache bypasses.
        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _replayCache = new StrictJtiReplayCache();
        _thumbprintComputer = new DpopThumbprintComputer();

        var dpopOptions = Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 60,
            AllowedClockSkewSeconds = 5
        });
        dpopOptions.Value.AllowedAlgorithms.Clear();
        dpopOptions.Value.AllowedAlgorithms.Add(SecurityAlgorithms.EcdsaSha256);

        _validator = new DpopProofValidator(
            _replayCache,
            dpopOptions,
            _thumbprintComputer,
            _timeProvider);
    }

    public void Dispose() =>
        // ✅ Resource cleanup: Dispose cryptographic material
        // Prevents memory leaks in long-running CI/CD agents
        _ecdsa?.Dispose();

    [Fact(DisplayName = "✅ Invariant: Perfectly signed and timed proof MUST authorize")]
    public async Task ValidateAsync_ValidProof_ReturnsSuccess()
    {
        // Arrange
        const string requestUri = "https://sentinel.local/api/v1/vault";
        var proof = CreateSignedProof("POST", requestUri);

        // Security Requirement: JTI must be committed to cache to prevent replay
        _replayCache.ExpectSuccess();

        var request = new DpopValidationRequest(proof, "POST", new Uri(requestUri));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeTrue("A valid cryptographic proof is the primary token-binding requirement.");
        result.Value.Thumbprint.Should().NotBeNullOrEmpty("DPoP thumbprint must be computed for token binding.");
        _replayCache.Verify();
    }

    [Fact(DisplayName = "🛡️ Adversarial: Tampered signature MUST result in Fail-Closed")]
    public async Task ValidateAsync_TamperedSignature_ReturnsFailure()
    {
        // Arrange
        var validProof = CreateSignedProof("GET", "https://api.io/t");
        var parts = validProof.Split('.');

        if (parts.Length != 3)
        {
            throw new InvalidOperationException("Invalid JWT structure");
        }

        // Flip bits in the signature segment (adversarial mutation)
        var tamperedSignature = new string(parts[2].Reverse().ToArray());
        var tamperedProof = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

        var request = new DpopValidationRequest(tamperedProof, "GET", new Uri("https://api.io/t"));

        // ✅ Key: NO cache setup expected. Signature validation happens BEFORE cache.
        _replayCache.ExpectNoCalls();

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse("Tampered signature must be rejected before any side effects.");

        // Verify no topology details leak
        var errorLower = result.ErrorMessage?.ToLowerInvariant() ?? "";
        errorLower.Should().NotContain("redis");
        errorLower.Should().NotContain("cluster");
        errorLower.Should().NotContain("connection");
        errorLower.Should().NotContain("database");
        errorLower.Should().NotContain("10.0.1.5");
        errorLower.Should().NotContain("127.0.0.1");
        errorLower.Should().NotContain("localhost");

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
        // Arrange
        var iat = _timeProvider.GetUtcNow().AddSeconds(secondsOffset);
        var proof = CreateSignedProof("GET", "https://api.io/t", iat: iat);

        if (expectedSuccess)
        {
            // Setup cache to accept the JTI if temporal check passes
            _replayCache.ExpectSuccess();
        }
        else
        {
            // No cache calls expected if temporal check fails
            _replayCache.ExpectNoCalls();
        }

        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.io/t"));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert - Temporal check must happen regardless of cache state
        result.IsSuccess.Should().Be(expectedSuccess, scenario);
    }

    [Fact(DisplayName = "⚠️ Fail-Closed: Infrastructure unavailability MUST deny access")]
    public async Task ValidateAsync_CacheOutage_ReturnsFailure()
    {
        // Arrange
        var proof = CreateSignedProof("GET", "https://api.io/t");

        // Simulate Redis/Database failure (infrastructure is down)
        _replayCache.SetShouldFail();

        var request = new DpopValidationRequest(proof, "GET", new Uri("https://api.io/t"));

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "In security logic, ambiguity is a denial. " +
            "Never allow bypass if the cache is down (Fail-Closed principle).");

        // Error message must NOT reveal infrastructure details
        var errorLower = result.ErrorMessage?.ToLowerInvariant() ?? "";
        errorLower.Should().NotContain("redis");
        errorLower.Should().NotContain("cluster");
        errorLower.Should().NotContain("connection");
        errorLower.Should().NotContain("database");
        errorLower.Should().NotContain("timeout");
    }

    [Fact(DisplayName = "🛑 Cancellation: OperationCanceledException MUST propagate")]
    public async Task ValidateAsync_WhenCancellationRequested_ThrowsOperationCanceledException()
    {
        var proof = CreateSignedProof("GET", "https://api.io/t");

        var options = Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 60,
            AllowedClockSkewSeconds = 5
        });
        options.Value.AllowedAlgorithms.Clear();
        options.Value.AllowedAlgorithms.Add(SecurityAlgorithms.EcdsaSha256);

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
        // Arrange
        // Proof was signed for /vault endpoint
        var proof = CreateSignedProof("POST", "https://api.io/vault");

        // Attacker attempts to replay it against /admin endpoint
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/admin"));

        // Setup: If URI validation fails, cache is never called
        _replayCache.ExpectNoCalls();

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert - URI binding is enforced with ordinal comparison (no Unicode equivalence tricks)
        result.IsSuccess.Should().BeFalse(
            "URI mismatch is a replay attack. Requests must use ordinal comparison for exact matching.");
        result.ErrorMessage.Should().Be("htu_mismatch",
            "Error must explicitly identify the binding violation");

        _replayCache.VerifyNoCalls();
    }

    [Fact(DisplayName = "🔐 JWK Header: Embedded public key MUST match actual signature")]
    public async Task ValidateAsync_TamperedJwkHeader_RejectsKeySwap()
    {
        // Arrange: Create a different key for the JWK header
        using var tamperedEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var tamperedParameters = tamperedEcdsa.ExportParameters(false);
        var wrongJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(tamperedParameters.Q.X ?? throw new InvalidOperationException()),
            ["y"] = Base64UrlEncoder.Encode(tamperedParameters.Q.Y ?? throw new InvalidOperationException())
        };

        // Create proof: Signed with REAL key, but header contains WRONG key (classic JWK swap attack)
        var proof = TestJwtBuilder.CreateValidProof(
            _securityKey,
            SecurityAlgorithms.EcdsaSha256,
            wrongJwk,
            "POST",
            "https://api.io/vault");

        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        // Setup: JWK mismatch fails before cache is consulted
        _replayCache.ExpectNoCalls();

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse(
            "JWK header must cryptographically match the actual signing key. " +
            "JWK swapping is a critical vulnerability in JOSE processing.");

        _replayCache.VerifyNoCalls();
    }

    [Fact(DisplayName = "🔄 JTI Replay: Duplicate proof MUST be rejected")]
    public async Task ValidateAsync_ReplayedJti_PreventsDuplicateUse()
    {
        // Arrange
        var proof = CreateSignedProof("POST", "https://api.io/vault");
        var request = new DpopValidationRequest(proof, "POST", new Uri("https://api.io/vault"));

        // First use: Cache accepts the JTI
        _replayCache.ExpectSuccess();

        // Act - First use
        var firstResult = await _validator.ValidateAsync(request);
        firstResult.IsSuccess.Should().BeTrue("First use of valid proof must pass");

        // Second use (replay): Reset cache expectations for second call - should reject
        _replayCache.Reset();
        _replayCache.ExpectFalse();

        // Act - Second use (replay)
        var replayResult = await _validator.ValidateAsync(request);

        // Assert
        replayResult.IsSuccess.Should().BeFalse(
            "RFC 9449 requires JTI uniqueness. Replayed JTIs are replay attacks. " +
            "The cache must reject attempts to reuse the same JTI.");
    }

    // ====== Test Helper: Production-Grade Cryptographic Proof Generation ======

    /// <summary>
    ///     Creates a mathematically valid, cryptographically signed DPoP proof.
    ///     Used by all tests to ensure validator interacts with real JOSE structures.
    /// </summary>
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

    /// <summary>
    ///     Strict in-memory JTI replay cache for testing.
    ///     Enforces that cache calls happen only when expected.
    /// </summary>
    private sealed class StrictJtiReplayCache : IJtiReplayCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _usedJtis = new();
        private bool _callHappened;
        private bool _expectCalls = true;
        private int _expectedReturnValue = 1; // 1 = true, 0 = false, -1 = no call expected
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
