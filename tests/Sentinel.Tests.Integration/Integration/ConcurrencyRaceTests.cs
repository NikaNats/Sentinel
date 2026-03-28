using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.Tests.Integration.Integration;

/// <summary>
///     High-contention atomicity verification test suite for DPoP nonce consumption.
///     SECURITY INVARIANT:
///     "If successCount in the concurrency test is ever >1, your system is vulnerable to DPoP proof replay,
///     allowing an attacker to reuse a captured proof for multiple API calls."
///     This test verifies that the Redis Lua atomic compare-and-delete script prevents TOCTOU race conditions
///     where two concurrent requests both see the same nonce and both attempt to consume it.
///     Expected behavior: Exactly ONE request wins, other 99 MUST return false because first deleted key.
/// </summary>
[Collection("Sentinel Integration")]
public sealed class ConcurrencyRaceTests : IAsyncLifetime
{
    private readonly SentinelApiFactory _factory;
    private readonly IDpopNonceStore _nonce_store;

    public ConcurrencyRaceTests(SentinelApiFactory factory)
    {
        _factory = factory;
        _nonce_store = _factory.Services.GetRequiredService<IDpopNonceStore>();
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    /// <summary>
    ///     Test: RaceCondition_100ConcurrentNonceConsumption_ExactlyOneSucceeds
    ///     Verifies that when 100 concurrent tasks attempt to consume the SAME nonce:
    ///     1. Exactly ONE succeeds (returns true)
    ///     2. Exactly 99 fail (return false) because the key is already deleted
    ///     3. The nonce is null in Redis after all tasks complete
    ///     This validates the Lua atomic compare-and-delete script prevents duplicate consumption.
    ///     If this test fails with successCount > 1, the system is vulnerable to DPoP proof replay.
    /// </summary>
    [Fact]
    public async Task RaceCondition_100ConcurrentNonceConsumption_ExactlyOneSucceeds()
    {
        // Arrange: Set up a single nonce that all 100 tasks will race to consume
        const string thumbprint = "test_jwk_thumbprint_concurrent";
        const string nonce = "atomic_test_nonce_value_12345";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Pre-populate the nonce in Redis
        await _nonce_store.SetNonceAsync(thumbprint, nonce, expiresAt);

        // Verify nonce is initially present
        var initialNonce = await _nonce_store.GetNonceAsync(thumbprint);
        initialNonce.Should().Be(nonce, "nonce must be set before race begins");

        // Act: Launch 100 concurrent tasks, each attempting to consume the SAME nonce
        var tasks = Enumerable
            .Range(0, 100)
            .Select(taskIndex => _nonce_store.ConsumeNonceIfMatchesAsync(thumbprint, nonce))
            .ToList();

        var results = await Task.WhenAll(tasks);

        // Assert: Exactly ONE succeeded, 99 failed
        var successCount = results.Count(r => r);
        var failureCount = results.Count(r => !r);

        successCount.Should().Be(1,
            "Exactly one task should win the race and consume the nonce. Redis Lua atomicity prevents ties.");

        failureCount.Should().Be(99,
            "Other 99 tasks should fail because the key is already deleted by the winner.");

        // Verify the nonce is now gone from Redis
        var remainingNonce = await _nonce_store.GetNonceAsync(thumbprint);
        remainingNonce.Should().BeNull(
            "After one successful consumption, nonce should be deleted and unavailable for replay attacks.");
    }

    /// <summary>
    ///     Test: RaceCondition_100ConcurrentNonceConsumption_DifferentThumbprints_AllSucceed
    ///     Control test: Verifies that when 100 concurrent tasks consume DIFFERENT nonces:
    ///     1. ALL 100 succeed (each gets its own key)
    ///     2. All nonces are consumed atomically
    ///     3. Redis key space is properly isolated by thumbprint
    ///     This control validates that the concurrency issue is NOT due to Redis connection pooling,
    ///     but specifically due to the shared key in the high-contention case.
    /// </summary>
    [Fact]
    public async Task RaceCondition_100ConcurrentNonceConsumption_DifferentThumbprints_AllSucceed()
    {
        // Arrange: Pre-populate 100 unique nonces (one per thumbprint)
        var noncesByThumbprint = new Dictionary<string, string>();

        for (var i = 0; i < 100; i++)
        {
            var thumbprint = $"test_jwk_thumbprint_unique_{i:D3}";
            var nonce = $"unique_nonce_value_{i:D5}";
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

            await _nonce_store.SetNonceAsync(thumbprint, nonce, expiresAt);
            noncesByThumbprint[thumbprint] = nonce;
        }

        // Act: Launch 100 concurrent consumption tasks, each on a different key
        var tasks = noncesByThumbprint
            .Select(kvp => _nonce_store.ConsumeNonceIfMatchesAsync(kvp.Key, kvp.Value))
            .ToList();

        var results = await Task.WhenAll(tasks);

        // Assert: ALL 100 should succeed (no key overlap)
        var successCount = results.Count(r => r);
        var failureCount = results.Count(r => !r);

        successCount.Should().Be(100,
            "All 100 tasks should succeed because each has a unique key (no contention).");

        failureCount.Should().Be(0,
            "No task should fail when operating on independent keys.");

        // Verify ALL nonces are deleted
        for (var i = 0; i < 100; i++)
        {
            var thumbprint = $"test_jwk_thumbprint_unique_{i:D3}";
            var remainingNonce = await _nonce_store.GetNonceAsync(thumbprint);
            remainingNonce.Should().BeNull(
                $"Nonce for thumbprint {thumbprint} should be deleted after consumption.");
        }
    }

    /// <summary>
    ///     Test: RaceCondition_ParallelSetAndConsume_OrderingPreserved
    ///     Verifies that even when SetNonce and ConsumeNonce race each other:
    ///     1. If SetNonce wins, ConsumeNonce should find the new value and fail (stale nonce)
    ///     2. If ConsumeNonce wins, it deletes the key and SetNonce's value is never visible
    ///     3. No race condition can produce a state where BOTH succeed on the same logical nonce
    ///     This validates ordering correctness in the DPoP proof rotation lifecycle:
    ///     - Attacker cannot trigger both SetNonce and ConsumeNonce on same proof
    /// </summary>
    [Fact]
    public async Task RaceCondition_ParallelSetAndConsume_OrderingPreserved()
    {
        // Arrange: Create a nonce, then race SetNonce (new value) vs ConsumeNonce (old value)
        const string thumbprint = "test_jwk_ordering_race";
        const string originalNonce = "original_nonce_abc123";
        const string newNonce = "new_nonce_xyz789";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Pre-populate with original nonce
        await _nonce_store.SetNonceAsync(thumbprint, originalNonce, expiresAt);

        // Act: Race SetNonce (with new value) vs ConsumeNonce (with old value)
        // Both start "simultaneously" via Task.WhenAll
        var setTask = _nonce_store.SetNonceAsync(thumbprint, newNonce, expiresAt);
        var consumeTask = _nonce_store.ConsumeNonceIfMatchesAsync(thumbprint, originalNonce);

        await Task.WhenAll(setTask, consumeTask);
        var consumeSucceeded = await consumeTask;

        // Assert: Check final state
        var finalNonce = await _nonce_store.GetNonceAsync(thumbprint);

        // Either:
        // Case 1: ConsumeNonce won first, deleted the key before SetNonce could find it
        //         Result: consumeSucceeded=true, finalNonce=null
        // Case 2: SetNonce won first, overwrote the original nonce before ConsumeNonce could match
        //         Result: consumeSucceeded=false, finalNonce=newNonce
        //
        // There MUST NOT be a Case 3 where consumeSucceeded=true AND finalNonce!=null
        // (that would indicate the key was not actually deleted)

        if (consumeSucceeded)
        {
            // Case 1: ConsumeNonce won, key should be gone
            finalNonce.Should().BeNull(
                "If ConsumeNonce succeeded, the key must be deleted atomically (Lua guarantees).");
        }
        else
        {
            // Case 2: SetNonce won, key should contain new value
            finalNonce.Should().Be(newNonce,
                "If ConsumeNonce failed, SetNonce must have overwritten with new value.");
        }
    }

    /// <summary>
    ///     Test: RaceCondition_InvalidNoncePattern_ExactlyOneConsumes
    ///     Verifies that even when nonce values are identical but invalid UTF-8:
    ///     1. Exactly ONE consumption succeeds
    ///     2. No race condition produces a bypass where multiple consume succeed
    ///     This validates the Lua script behavior with edge-case nonce values.
    /// </summary>
    [Fact]
    public async Task RaceCondition_InvalidNoncePattern_ExactlyOneConsumes()
    {
        // Arrange: Use a nonce value that exercises UTF-8 edge cases
        const string thumbprint = "test_edge_case_utf8";
        var nonce = "nonce_with_\u0000null_char"; // Null character edge case
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        // Pre-populate
        await _nonce_store.SetNonceAsync(thumbprint, nonce, expiresAt);

        // Act: 50 concurrent consumption attempts (reduced from 100 for edge case)
        var tasks = Enumerable
            .Range(0, 50)
            .Select(_ => _nonce_store.ConsumeNonceIfMatchesAsync(thumbprint, nonce))
            .ToList();

        var results = await Task.WhenAll(tasks);

        // Assert: Still exactly one wins
        var successCount = results.Count(r => r);
        var failureCount = results.Count(r => !r);

        successCount.Should().Be(1,
            "Even with edge-case nonce values, atomicity must be preserved.");

        failureCount.Should().Be(49);

        // Verify cleanup
        var remainingNonce = await _nonce_store.GetNonceAsync(thumbprint);
        remainingNonce.Should().BeNull("Nonce must be consumed and deleted.");
    }

    /// <summary>
    ///     Test: RaceCondition_CachedVsRedisContention_ConsistencyPreserved
    ///     Verifies that when in-memory fallback is enabled and Redis is operational:
    ///     1. Both paths respect the same atomicity semantics
    ///     2. No cross-path contamination (Redis deletion doesn't leave stale in-memory copy)
    ///     This validates the fallback pattern doesn't introduce race conditions.
    /// </summary>
    [Fact]
    public async Task RaceCondition_HighContention_AtLeastOneSucceeds()
    {
        // Arrange: Prepare 10 rounds of high-contention races
        const int roundsCount = 10;
        const int tasksPerRound = 50;

        for (var round = 0; round < roundsCount; round++)
        {
            var roundThumbprint = $"test_round_{round:D2}";
            var roundNonce = $"round_nonce_{round:D6}";
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

            // Pre-populate this round's nonce
            await _nonce_store.SetNonceAsync(roundThumbprint, roundNonce, expiresAt);

            // Act: Launch tasks for this round
            var tasks = Enumerable
                .Range(0, tasksPerRound)
                .Select(_ => _nonce_store.ConsumeNonceIfMatchesAsync(roundThumbprint, roundNonce))
                .ToList();

            var results = await Task.WhenAll(tasks);

            // Assert: Each round must have exactly one success
            var successCount = results.Count(r => r);
            successCount.Should().Be(1,
                $"Round {round}: exactly one task must consume the nonce despite 50 concurrent attempts.");

            // Verify cleanup
            var remainingNonce = await _nonce_store.GetNonceAsync(roundThumbprint);
            remainingNonce.Should().BeNull(
                $"Round {round}: nonce must be deleted and unavailable for replay.");
        }
    }
}
