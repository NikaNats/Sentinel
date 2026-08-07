using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using Sentinel.AspNetCore;
using Sentinel.Security.Abstractions.Exceptions;
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

    [Fact(DisplayName = "🔴 Defect D Verification: Infrastructure exceptions must PROPAGATE (never be swallowed as false)")]
    public async Task TryStoreNonceAsync_WhenInfrastructureFails_PropagatesException()
    {
        _storeMock
            .Setup(x => x.SetNonceAsync(_thumbprint, _nonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NonceStoreUnavailableException("Redis cluster connection pool exhausted"));

        var act = async () =>
            await _storeMock.Object.TryStoreNonceAsync(_thumbprint, _nonce, TimeSpan.FromMinutes(5),
                TestCancellationToken);

        // Fail-closed mandate: the outage must bubble up to the middleware so it
        // returns 503 + Retry-After, NOT be masked as a client nonce mismatch (401).
        await act.Should().ThrowAsync<NonceStoreUnavailableException>();
    }
}
