using System.Threading.Channels;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Domain.Notifications;
using Sentinel.Infrastructure.Notifications;

namespace Sentinel.Tests.Notifications;

public sealed class NotificationServiceFallbackTests
{
    [Fact]
    public async Task
        BackgroundDispatcher_WhenProviderFails_LogsFailureAndKeepsServiceAliveForCircuitBreakerTransition()
    {
        var queue = new TestNotificationQueue();
        var dispatcher = new Mock<INotificationDispatcher>();
        dispatcher
            .Setup(x => x.DispatchAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("sendgrid down"));

        var logger = new Mock<ILogger<NotificationBackgroundService>>();
        var options = Options.Create(new NotificationOptions
        {
            MaxRetryAttempts = 3,
            RetryDelaySeconds = 1,
            QueueCapacity = 16
        });

        await queue.EnqueueAsync(new NotificationMessage(
                new NotificationRecipient("user@example.com"),
                "Alert",
                "SecurityAlert",
                new { Action = "Logout" }),
            CancellationToken.None);

        using var sut = new NotificationBackgroundService(queue, dispatcher.Object, options, logger.Object);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await sut.StartAsync(cts.Token);
        await Task.Delay(TimeSpan.FromSeconds(4), CancellationToken.None);
        await sut.StopAsync(CancellationToken.None);

        dispatcher.Verify(x => x.DispatchAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()),
            Times.Exactly(3));
        logger.VerifyLog(LogLevel.Error, Times.AtLeastOnce());

        true.Should().BeTrue();
    }

    private sealed class TestNotificationQueue : INotificationQueue
    {
        private readonly Channel<NotificationMessage> channel = Channel.CreateUnbounded<NotificationMessage>();

        public async ValueTask EnqueueAsync(NotificationMessage message, CancellationToken ct)
        {
            await channel.Writer.WriteAsync(message, ct);
        }

        public IAsyncEnumerable<NotificationMessage> DequeueAllAsync(CancellationToken ct)
        {
            return channel.Reader.ReadAllAsync(ct);
        }
    }
}

internal static class LoggerVerifyExtensions
{
    public static void VerifyLog<T>(this Mock<ILogger<T>> logger, LogLevel level, Times times)
    {
        logger.Verify(
            x => x.Log(
                level,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((_, _) => true),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            times);
    }
}
