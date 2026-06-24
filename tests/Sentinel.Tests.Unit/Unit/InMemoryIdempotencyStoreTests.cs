using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Time.Testing;
using Sentinel.AspNetCore.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class InMemoryIdempotencyStoreTests
{
    private readonly FakeTimeProvider _timeProvider;
    private readonly InMemoryIdempotencyStore _sut;
    private const string RequestKey = "idempotency:user-1:payment-txn-999";
    private readonly TimeSpan _inProgressTtl = TimeSpan.FromSeconds(5);
    private readonly TimeSpan _completedTtl = TimeSpan.FromHours(24);

    public InMemoryIdempotencyStoreTests()
    {
        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _sut = new InMemoryIdempotencyStore(_timeProvider);
    }

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    [Fact(DisplayName = "✅ Idempotency: First attempt successfully acquires the lock")]
    public async Task TryAcquireAsync_FirstTime_ReturnsAcquired()
    {
        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.Acquired);
        cachedResponse.Should().BeNull("New requests do not have any cached response.");
    }

    [Fact(DisplayName = "🔴 Idempotency: Second attempt while request is in progress returns InProgress")]
    public async Task TryAcquireAsync_WhileInProgress_ReturnsInProgress()
    {
        _ = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.InProgress);
        cachedResponse.Should().BeNull();
    }

    [Fact(DisplayName = "✅ Idempotency: MarkCompleted saves the response and subsequent acquires replay it")]
    public async Task MarkCompletedAsync_SavesResponse_AndSubsequentCallsReplayIt()
    {
        _ = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        var expectedResponse = new CachedHttpResponse(201, "application/json", "{\"id\":\"doc-123\"}"u8.ToArray());
        await _sut.MarkCompletedAsync(RequestKey, expectedResponse, _completedTtl, TestCancellationToken);

        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.Completed);
        cachedResponse.Should().NotBeNull();
        cachedResponse!.StatusCode.Should().Be(201);
        cachedResponse.ContentType.Should().Be("application/json");
        cachedResponse.Body.Should().BeEquivalentTo(expectedResponse.Body);
    }

    [Fact(DisplayName = "⏱️ Idempotency: InProgress lock automatically expires and allows re-acquisition")]
    public async Task TryAcquireAsync_WhenInProgressExpires_PrunesAndAllowsReAcquisition()
    {
        _ = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        _timeProvider.Advance(TimeSpan.FromSeconds(6));

        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.Acquired);
        cachedResponse.Should().BeNull();
    }

    [Fact(DisplayName = "⏱️ Idempotency: Completed cache automatically expires and allows re-execution")]
    public async Task TryAcquireAsync_WhenCompletedExpires_PrunesAndAllowsReExecution()
    {
        _ = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);
        var response = new CachedHttpResponse(200, "application/json", "{\"status\":\"ok\"}"u8.ToArray());
        await _sut.MarkCompletedAsync(RequestKey, response, _completedTtl, TestCancellationToken);

        _timeProvider.Advance(TimeSpan.FromHours(25));

        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.Acquired);
        cachedResponse.Should().BeNull();
    }

    [Fact(DisplayName = "✓ Idempotency: ReleaseAsync deletes the key and allows immediate re-acquisition")]
    public async Task ReleaseAsync_DeletesKey_AndAllowsImmediateReAcquisition()
    {
        _ = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        await _sut.ReleaseAsync(RequestKey, TestCancellationToken);

        var (state, cachedResponse) = await _sut.TryAcquireAsync(RequestKey, _inProgressTtl, TestCancellationToken);

        state.Should().Be(IdempotencyAcquireResult.Acquired);
        cachedResponse.Should().BeNull();
    }
}
