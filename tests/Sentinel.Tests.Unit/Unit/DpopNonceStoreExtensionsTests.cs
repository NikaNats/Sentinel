using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using Moq.Protected;
using Sentinel.AspNetCore;
using Sentinel.Security.Abstractions.Nonce;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopNonceStoreExtensionsTests
{
    private readonly Mock<IDpopNonceStore> _storeMock;
    private readonly string _thumbprint = "test-client-jwk-thumbprint-12345";
    private readonly string _nonce = "active-cryptographic-nonce-value";

    public DpopNonceStoreExtensionsTests()
    {
        _storeMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
    }

    private static CancellationToken TestCancellationToken => TestContext.Current.CancellationToken;

    [Fact(DisplayName = "✅ Extension: TryStoreNonceAsync successfully stores nonce and returns true")]
    public async Task TryStoreNonceAsync_SuccessfulStore_ReturnsTrue()
    {
        var ttl = TimeSpan.FromMinutes(5);
        _storeMock
            .Setup(x => x.SetNonceAsync(_thumbprint, _nonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable();

        var result = await _storeMock.Object.TryStoreNonceAsync(_thumbprint, _nonce, ttl, TestCancellationToken);

        result.Should().BeTrue();
        _storeMock.Verify();
    }

    [Fact(DisplayName = "🔴 Extension: TryStoreNonceAsync shields database exception and returns false (Fail-Closed)")]
    public async Task TryStoreNonceAsync_WhenDatabaseThrows_ReturnsFalse()
    {
        _storeMock
            .Setup(x => x.SetNonceAsync(_thumbprint, _nonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis cluster connection pool exhausted"));

        var result = await _storeMock.Object.TryStoreNonceAsync(_thumbprint, _nonce, TimeSpan.FromMinutes(5), TestCancellationToken);

        result.Should().BeFalse("Exceptions in the storage layer must be shielded and returned as false (Fail-Closed).");
    }

    [Fact(DisplayName = "✅ Extension: ConsumeNonceIfMatchesAsync returns true and clears key on successful match")]
    public async Task ConsumeNonceIfMatchesAsync_WhenNonceMatches_ClearsAndReturnsTrue()
    {
        _storeMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(_nonce);

        _storeMock
            .Setup(x => x.SetNonceAsync(_thumbprint, string.Empty, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask)
            .Verifiable();

        var result = await DpopNonceStoreExtensions.ConsumeNonceIfMatchesAsync(_storeMock.Object, _thumbprint, _nonce, TestCancellationToken);

        result.Should().BeTrue();
        _storeMock.Verify();
    }

    [Fact(DisplayName = "🔴 Extension: ConsumeNonceIfMatchesAsync returns false on mismatched expected nonce")]
    public async Task ConsumeNonceIfMatchesAsync_WhenNonceMismatches_ReturnsFalse()
    {
        _storeMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync("different-stored-nonce-value");

        var result = await DpopNonceStoreExtensions.ConsumeNonceIfMatchesAsync(_storeMock.Object, _thumbprint, _nonce, TestCancellationToken);

        result.Should().BeFalse();

        _storeMock.Verify(x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact(DisplayName = "🔴 Extension: ConsumeNonceIfMatchesAsync returns false when no nonce exists in store")]
    public async Task ConsumeNonceIfMatchesAsync_WhenNoNonceInStore_ReturnsFalse()
    {
        _storeMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        var result = await DpopNonceStoreExtensions.ConsumeNonceIfMatchesAsync(_storeMock.Object, _thumbprint, _nonce, TestCancellationToken);

        result.Should().BeFalse();
    }

    [Fact(DisplayName = "🔴 Extension: ConsumeNonceIfMatchesAsync shields GetNonce exception and returns false")]
    public async Task ConsumeNonceIfMatchesAsync_WhenGetNonceThrows_ReturnsFalse()
    {
        _storeMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis read timeout"));

        var result = await DpopNonceStoreExtensions.ConsumeNonceIfMatchesAsync(_storeMock.Object, _thumbprint, _nonce, TestCancellationToken);

        result.Should().BeFalse();
    }

    [Fact(DisplayName = "🔴 Extension: ConsumeNonceIfMatchesAsync shields SetNonce (clearance) exception and returns false")]
    public async Task ConsumeNonceIfMatchesAsync_WhenSetNonceThrows_ReturnsFalse()
    {
        _storeMock
            .Setup(x => x.GetNonceAsync(_thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(_nonce);

        _storeMock
            .Setup(x => x.SetNonceAsync(_thumbprint, string.Empty, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Redis write connection lost"));

        var result = await DpopNonceStoreExtensions.ConsumeNonceIfMatchesAsync(_storeMock.Object, _thumbprint, _nonce, TestCancellationToken);

        result.Should().BeFalse();
    }
}
