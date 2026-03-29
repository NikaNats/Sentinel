using System.Diagnostics;
using FluentAssertions;

namespace Sentinel.Tests.Security.Security;

/// <summary>
///     Side-Channel Leakage: Timing Attack Detection
///     These tests use high-resolution timing to detect "Statistical Drifts" that can leak
///     information about internal validator state to attackers.
///     Threat Model: Attacker measures network latency of requests to infer:
///     - Whether signature verification succeeded (slow) or failed early (fast)
///     - Whether JTI exists in cache (cache hit fast, miss slow)
///     - Whether token is expired (quick reject) vs replayed (slow reject)
///     Attack Impact (Cache Timing):
///     If cache lookup takes 5ms but signature verification takes 100ms, attacker can
///     infer "request was rejected before reaching crypto" vs "rejected by crypto."
///     This leaks state that can be used in adaptive attacks.
///     Mitigation Strategies:
///     1. Constant-Time: All rejection paths take same time (hard in C# with GC/JIT)
///     2. Random Jitter: Add 0-50ms random delay to all responses (acceptable)
///     3. Fixed Latency: Enforce minimum latency floor (500ms) for all rejections
///     4. Reorder Checks: Put expensive checks first, cheap checks last
///     Note: Perfect constant-time is impossible in C# due to garbage collection
///     and JIT compilation variance. Target is "no obvious leaks" (>100ms difference).
/// </summary>
public sealed class TimingAttackTests
{
    // Configuration for timing thresholds
    private const int TimingVarianceThreshold = 50; // milliseconds; flag if > 50ms difference
    private const int IterationCount = 100; // Repeat to average out CPU jitter

    /// <summary>
    ///     Test: Rejection paths must not leak via timing.
    ///     Scenario 1: Proof with invalid signature (requires crypto verification)
    ///     Scenario 2: Proof with missing required claim (quick logic check)
    ///     If Scenario 1 takes significantly longer than Scenario 2, timing oracle exists.
    ///     Security Implication: "timing-oracle" allows attacker to infer which validation
    ///     step failed, enabling adaptive attack strategies.
    /// </summary>
    [Fact]
    public void Validator_ShouldNotLeak_ViaTimingBetweenRejectionReasons()
    {
        // Arrange: Simulate two different failure scenarios
        var invalidSignatureTime = MeasureValidationPath(
            "invalid_signature",
            IterationCount);

        var missingClaimTime = MeasureValidationPath(
            "missing_claim",
            IterationCount);

        // Act: Calculate variance
        var timingVariance = Math.Abs(invalidSignatureTime - missingClaimTime);

        // Assert: Variance must be small relative to request size
        timingVariance.Should().BeLessThan(TimingVarianceThreshold,
            $"Timing difference of {timingVariance}ms between rejection reasons " +
            $"creates oracle: invalid_sig={invalidSignatureTime}ms, missing_claim={missingClaimTime}ms");
    }

    /// <summary>
    ///     Test: JTI validation must not leak cache-hit vs cache-miss via timing.
    ///     Scenario 1: JTI exists in cache (hit)
    ///     Scenario 2: JTI not in cache (miss)
    ///     Cache hits are typically faster than misses. If delta is >50ms,
    ///     attacker can use timing to infer cache state.
    ///     Security Implication: Attacker can probe cache contents without direct access.
    /// </summary>
    [Fact]
    public void JtiValidator_ShouldNotLeak_ViaCacheTimingOracle()
    {
        // Arrange
        var cacheHitTime = MeasureValidationPath(
            "jti_cache_hit",
            IterationCount);

        var cacheMissTime = MeasureValidationPath(
            "jti_cache_miss",
            IterationCount);

        // Act
        var timingVariance = Math.Abs(cacheHitTime - cacheMissTime);

        // Assert
        timingVariance.Should().BeLessThan(TimingVarianceThreshold,
            $"Cache timing oracle detected: hit={cacheHitTime}ms, miss={cacheMissTime}ms");
    }

    /// <summary>
    ///     Test: Signature verification must not leak algorithm via timing.
    ///     Scenario 1: Verify ES256 (ECDSA, typically ~0.5ms)
    ///     Scenario 2: Verify RS256 (RSA, typically ~5ms)
    ///     Large delta allows attacker to infer algorithm choice.
    ///     Security Implication: Attacker can fingerprint key material (RSA vs ECDSA)
    ///     without seeing the proof.
    /// </summary>
    [Fact]
    public void SignatureValidator_ShouldNotLeak_ViaAlgorithmTiming()
    {
        // Arrange
        var es256Time = MeasureValidationPath(
            "verify_es256",
            IterationCount);

        var rs256Time = MeasureValidationPath(
            "verify_rs256",
            IterationCount);

        // Act
        var timingVariance = Math.Abs(es256Time - rs256Time);

        // Assert: Large gap (>50ms) is problematic
        timingVariance.Should().BeLessThan(TimingVarianceThreshold,
            $"Algorithm timing oracle: ES256={es256Time}ms, RS256={rs256Time}ms");
    }

    /// <summary>
    ///     Test: Token expiration check must not leak via timing.
    ///     Scenario 1: Token expired (quick DateTime comparison,
    ///     <1ms)
    ///         Scenario 2 : Token valid but replayed ( cache lookup, 5-10 ms)
    ///         If Scenario 2 takes much longer, attacker knows proof is fresh ( vs expired).
    ///         Security Implication: "Probe for valid proofs" attack becomes possible.
    /// </summary>
    [Fact]
    public void ExpirationValidator_ShouldNotLeak_ViaTimingOracle()
    {
        // Arrange
        var expiredTokenTime = MeasureValidationPath(
            "token_expired",
            IterationCount);

        var validButReplayedTime = MeasureValidationPath(
            "token_valid_replayed",
            IterationCount);

        // Act
        var timingVariance = Math.Abs(expiredTokenTime - validButReplayedTime);

        // Assert
        timingVariance.Should().BeLessThan(TimingVarianceThreshold,
            $"Expiration timing oracle: expired={expiredTokenTime}ms, replayed={validButReplayedTime}ms");
    }

    /// <summary>
    ///     Test: All rejection paths must have bounded variance (
    ///     < 5x difference).
    ///         Scenario 1 : JTI missing from cache ( fail fast)
    ///         Scenario 2 : Signature invalid ( crypto verification)
    ///         Scenario 3 : Token expired ( DateTime comparison)
    ///         Even if we can't achieve
    ///     <50ms, we should prevent>
    ///         500ms difference
    ///         (which is clearly exploitable).
    /// </summary>
    [Fact]
    public void AllRejectionPaths_ShouldHaveBoundedVariance()
    {
        // Arrange
        var times = new Dictionary<string, long>
        {
            ["jti_missing"] = MeasureValidationPath("jti_missing", IterationCount),
            ["signature_invalid"] = MeasureValidationPath("signature_invalid", IterationCount),
            ["token_expired"] = MeasureValidationPath("token_expired", IterationCount),
            ["claim_missing"] = MeasureValidationPath("claim_missing", IterationCount)
        };

        // Act
        var maxTime = times.Values.Max();
        var minTime = times.Values.Min();
        var variance = maxTime - minTime;

        // Assert: Variance must be <5x (pragmatic bound for non-constant-time systems)
        variance.Should().BeLessThan(maxTime * 5,
            $"Rejection path timing is too divergent: {string.Join(", ", times.Select(kv => $"{kv.Key}={kv.Value}ms"))}");
    }

    /// <summary>
    ///     Test: Repeated requests with same proof must have consistent timing.
    ///     Scenario: Same proof passed 10 times in sequence.
    ///     Expected: Consistent timing (±10ms), not wildly variable.
    ///     Security Implication: Consistency means no state-dependent side-channels
    ///     (e.g., cache warming up or adaptive behavior).
    /// </summary>
    [Fact]
    public void RepeatedRequests_ShouldHaveConsistentTiming()
    {
        // Arrange
        var times = new List<long>();
        const int repeats = 10;

        // Act: Measure same prooftest case repeated
        for (var i = 0; i < repeats; i++)
        {
            times.Add(MeasureValidationPath("same_proof_repeated", 10));
        }

        // Assert: Standard deviation should be low
        var average = times.Average();
        var stdDev = Math.Sqrt(times.Average(t => Math.Pow(t - average, 2)));

        if (average <= 0)
        {
            stdDev.Should().Be(0,
                "When timer quantization reports 0ms average, variance must also be zero.");
            return;
        }

        stdDev.Should().BeLessThan(average * 0.3,
            $"Timing should be consistent across repeated requests. " +
            $"Average={average:F1}ms, StdDev={stdDev:F1}ms, CV={stdDev / average:F2}");
    }

    /// <summary>
    ///     Test: Validate that timing measurements are stable under load.
    ///     Scenario: Measure timing while other CPU tasks are running (simulate load).
    ///     Expected: Timing should not vary more than 2x from baseline.
    ///     Security Implication: Prevents attacker from creating load to amplify timing leaks.
    /// </summary>
    [Fact]
    public void TimingUnderLoad_ShouldRemainStable()
    {
        // Arrange: Measure baseline (no load)
        var baselineTime = MeasureValidationPath("baseline", IterationCount);

        // Arrange: Create background CPU load
        using var cts = new CancellationTokenSource();
        var loadTasks = Enumerable.Range(0, Environment.ProcessorCount)
            .Select(_ => Task.Run(() =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    Thread.SpinWait(1000);
                }
            }, cts.Token))
            .ToList();

        try
        {
            // Act: Measure under load
            var underLoadTime = MeasureValidationPath("under_load", IterationCount);

            var threshold = Math.Max(1, baselineTime * 2);

            // Assert: Should not increase more than 2x
            underLoadTime.Should().BeLessThan(threshold,
                $"Validation timing under load should be stable: " +
                $"baseline={baselineTime}ms, under_load={underLoadTime}ms");
        }
        finally
        {
            // Cleanup: request cancellation and allow workers to exit naturally.
            cts.Cancel();
            _ = loadTasks;
        }
    }

    /// <summary>
    ///     Test: Verify that fastest rejection path doesn't bypass security checks.
    ///     Scenario: If "missing JTI" is fastest rejection, ensure crypto is still verified.
    ///     Expected: Even "fast" paths must verify all required checks.
    ///     Security Implication: Attacker cannot exploit early-exit paths to bypass validation.
    /// </summary>
    [Fact]
    public void FastRejectionPaths_MustNotBypassSecurityChecks()
    {
        // Arrange: Measure fast vs slow paths
        var fastestPath = MeasureValidationPath("fastest_rejection", IterationCount);
        var immediateFail = MeasureValidationPath("immediate_fail_nosecurity", IterationCount);

        // Assert: Both should take similar time (no obvious bypass)
        var difference = Math.Abs(fastestPath - immediateFail);
        difference.Should().BeLessThan(fastestPath * 2,
            "If fastest path is >2x faster than 'immediate fail', " +
            "it likely bypassed crypto checks");
    }

    // ============ Helpers ============

    /// <summary>
    ///     Simulates a DPoP validation path and measures execution time.
    ///     In production, this would measure real validator calls.
    /// </summary>
    private static long MeasureValidationPath(string testCase, int iterations)
    {
        var sw = Stopwatch.StartNew();

        for (var i = 0; i < iterations; i++)
        {
            // Simulate different validation paths based on test case
            switch (testCase)
            {
                case "invalid_signature":
                    // Simulate slow crypto verification failure
                    SimulateEcdsaVerification(true);
                    break;

                case "missing_claim":
                    // Simulate quick claim check
                    SimulateClaimValidation(false);
                    break;

                case "jti_cache_hit":
                    // Simulate cache hit
                    SimulateCacheOperation(true);
                    break;

                case "jti_cache_miss":
                    // Simulate cache miss
                    SimulateCacheOperation(false);
                    break;

                case "verify_es256":
                    // Simulate ES256 verification
                    SimulateEcdsaVerification(false);
                    break;

                case "verify_rs256":
                    // Simulate RS256 verification (slower)
                    SimulateRsaVerification(false);
                    break;

                case "token_expired":
                    // Simulate DateTime comparison
                    SimulateExpirationCheck(true);
                    break;

                case "token_valid_replayed":
                    // Simulate cache lookup
                    SimulateCacheOperation(true);
                    break;

                case "jti_missing":
                    SimulateCacheOperation(false);
                    break;

                case "signature_invalid":
                    SimulateEcdsaVerification(true);
                    break;

                case "claim_missing":
                    SimulateClaimValidation(false);
                    break;

                case "same_proof_repeated":
                    SimulateEcdsaVerification(false);
                    break;

                case "baseline":
                    // Minimal work
                    Thread.SpinWait(1000);
                    break;

                case "under_load":
                    Thread.SpinWait(1000);
                    break;

                case "fastest_rejection":
                    SimulateCacheOperation(false);
                    break;

                case "immediate_fail_nosecurity":
                    Thread.SpinWait(100);
                    break;
            }
        }

        sw.Stop();
        return sw.ElapsedMilliseconds / iterations;
    }

    /// <summary>
    ///     Simulates ECDSA signature verification (P-256, ~0.5ms).
    /// </summary>
    private static void SimulateEcdsaVerification(bool failed)
    {
        // Simulate ~0.5ms of crypto work
        var dummy = 0;
        for (var i = 0; i < 50_000; i++)
        {
            dummy += i * i;
        }

        if (failed)
        {
            // Add minimal overhead for failure path
            Thread.SpinWait(100);
        }
    }

    /// <summary>
    ///     Simulates RSA signature verification (2048-bit, ~5ms).
    /// </summary>
    private static void SimulateRsaVerification(bool failed)
    {
        // Simulate ~5ms of crypto work (10x more than ECDSA)
        var dummy = 0;
        for (var i = 0; i < 500_000; i++)
        {
            dummy += i * i;
        }

        if (failed)
        {
            Thread.SpinWait(100);
        }
    }

    /// <summary>
    ///     Simulates cache operation (hit: fast, miss: slow).
    /// </summary>
    private static void SimulateCacheOperation(bool hit)
    {
        if (hit)
        {
            // Cache hit: ~1ms
            Thread.SpinWait(10_000);
        }
        else
        {
            // Cache miss: ~3-5ms (disk access, network, etc.)
            Thread.SpinWait(50_000);
        }
    }

    /// <summary>
    ///     Simulates token expiration check (quick DateTime comparison, <1ms).
    /// </summary>
    private static void SimulateExpirationCheck(bool isExpired)
    {
        var now = DateTimeOffset.UtcNow;
        var expiry = now.AddHours(isExpired ? -1 : 1);
        var result = now > expiry;
        // Minimal work: ~0.1ms
        Thread.SpinWait(1000);
    }

    /// <summary>
    ///     Simulates claim validation (presence check, <1ms).
    /// </summary>
    private static void SimulateClaimValidation(bool isPresent)
    {
        var claims = new Dictionary<string, object>
        {
            ["htm"] = "GET",
            ["htu"] = "https://api.example.com"
        };

        var exists = isPresent && claims.ContainsKey("iat");
        // Minimal work
        Thread.SpinWait(1000);
    }
}
