using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

internal sealed class NotificationQueue(IOptions<NotificationOptions> options) : INotificationQueue
{
    private readonly Channel<NotificationMessage> channel = Channel.CreateBounded<NotificationMessage>(
        new BoundedChannelOptions(Math.Max(options.Value.QueueCapacity, 64))
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

    public ValueTask EnqueueAsync(NotificationMessage message, CancellationToken ct)
    {
        return channel.Writer.WriteAsync(message, ct);
    }

    public IAsyncEnumerable<NotificationMessage> DequeueAllAsync(CancellationToken ct)
    {
        return channel.Reader.ReadAllAsync(ct);
    }
}
