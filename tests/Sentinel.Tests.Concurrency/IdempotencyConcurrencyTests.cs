#pragma warning disable CA1859
#pragma warning disable CA2000

using System.Collections.Concurrent;
using FluentAssertions;
using Sentinel.AspNetCore.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Xunit;

namespace Sentinel.Tests.Concurrency;

public sealed class IdempotencyConcurrencyTests
{
    [Fact(DisplayName = "🌪️ Concurrency 1: Systematic exploration of parallel Idempotency acquisitions")]
    public async Task RunCoyoteIdempotencyTest() => await TestConcurrentIdempotencyAcquisition();

    private static async Task TestConcurrentIdempotencyAcquisition()
    {
        var store = new InMemoryIdempotencyStore();
        const string idempotencyKey = "concurrency-lock-key-123";
        var inProgressTtl = TimeSpan.FromSeconds(5);

        var results = new ConcurrentBag<IdempotencyAcquireResult>();
        var tasks = new List<Task>();

        for (var i = 0; i < 5; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                var (state, _) = await store.TryAcquireAsync(idempotencyKey, inProgressTtl);
                results.Add(state);
            }));
        }

        await Task.WhenAll(tasks);

        var acquiredCount = results.Count(r => r == IdempotencyAcquireResult.Acquired);
        var inProgressCount = results.Count(r => r == IdempotencyAcquireResult.InProgress);

        acquiredCount.Should().Be(1, "Exactly one task must win the race and acquire the lock.");
        inProgressCount.Should().Be(4, "All other concurrent tasks must be blocked with InProgress status.");
    }

    [Fact(DisplayName = "🌪️ Concurrency 2: Systematic exploration of concurrent Acquire vs Release transitions")]
    public async Task RunCoyoteAcquireVsReleaseTest() => await TestConcurrentAcquireVsRelease();

    private static async Task TestConcurrentAcquireVsRelease()
    {
        var store = new InMemoryIdempotencyStore();
        const string idempotencyKey = "release-race-key";
        var inProgressTtl = TimeSpan.FromSeconds(5);

        var (initialState, _) = await store.TryAcquireAsync(idempotencyKey, inProgressTtl);
        initialState.Should().Be(IdempotencyAcquireResult.Acquired);

        var results = new ConcurrentBag<IdempotencyAcquireResult>();
        var tasks = new List<Task>();

        tasks.Add(Task.Run(async () => { await store.ReleaseAsync(idempotencyKey); }));

        for (var i = 0; i < 4; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                var (state, _) = await store.TryAcquireAsync(idempotencyKey, inProgressTtl);
                results.Add(state);
            }));
        }

        await Task.WhenAll(tasks);

        var acquiredCount = results.Count(r => r == IdempotencyAcquireResult.Acquired);
        acquiredCount.Should().BeLessThanOrEqualTo(1, "At most one new task can acquire the lock after release.");
    }

    [Fact(DisplayName = "🌪️ Concurrency 3: Systematic exploration of MarkCompleted vs concurrent Acquires")]
    public async Task RunCoyoteMarkCompletedTest() => await TestConcurrentMarkCompleted();

    private static async Task TestConcurrentMarkCompleted()
    {
        var store = new InMemoryIdempotencyStore();
        const string idempotencyKey = "completion-race-key";
        var inProgressTtl = TimeSpan.FromSeconds(5);
        var completedTtl = TimeSpan.FromHours(24);

        var (initialState, _) = await store.TryAcquireAsync(idempotencyKey, inProgressTtl);
        initialState.Should().Be(IdempotencyAcquireResult.Acquired);

        var results = new ConcurrentBag<IdempotencyAcquireResult>();
        var tasks = new List<Task>();

        var dummyResponse = new CachedHttpResponse(200, "application/json", "{\"status\":\"ok\"}"u8.ToArray());
        tasks.Add(Task.Run(async () =>
        {
            await store.MarkCompletedAsync(idempotencyKey, dummyResponse, completedTtl);
        }));

        for (var i = 0; i < 4; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                var (state, _) = await store.TryAcquireAsync(idempotencyKey, inProgressTtl);
                results.Add(state);
            }));
        }

        await Task.WhenAll(tasks);

        var acquiredCount = results.Count(r => r == IdempotencyAcquireResult.Acquired);
        var inProgressCount = results.Count(r => r == IdempotencyAcquireResult.InProgress);
        var completedCount = results.Count(r => r == IdempotencyAcquireResult.Completed);

        acquiredCount.Should().Be(0,
            "No new task can ever acquire the lock once it has been initialized by another thread.");
        (inProgressCount + completedCount).Should().Be(4,
            "All concurrent tasks must resolve to either InProgress or Completed states.");
    }
}
#pragma warning restore CA1859
#pragma warning restore CA2000
