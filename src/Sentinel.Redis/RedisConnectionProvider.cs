namespace Sentinel.Redis;

internal sealed class RedisConnectionProvider : IRedisConnectionProvider
{
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private readonly ILogger<RedisConnectionProvider> _logger;
    private readonly ConfigurationOptions _options;
    private bool _disposed;
    private ConnectionMultiplexer? _multiplexer;

    public RedisConnectionProvider(RedisOptions redisOptions, ILogger<RedisConnectionProvider> logger)
    {
        _logger = logger;

        _options = ConfigurationOptions.Parse(redisOptions.EndPoint ?? "localhost:6379");
        _options.Ssl = redisOptions.UseSsl;
        _options.Password = redisOptions.Password;

        _options.AbortOnConnectFail = false;
        _options.ConnectRetry = 5;

        _options.ConnectTimeout = redisOptions.SyncTimeout;
        _options.SyncTimeout = redisOptions.SyncTimeout;
        _options.AsyncTimeout = redisOptions.SyncTimeout;

        _options.ChannelPrefix = RedisChannel.Literal("sentinel");
    }

#pragma warning disable CA1508
    public async ValueTask<IConnectionMultiplexer> GetConnectionAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_multiplexer != null)
        {
            return _multiplexer;
        }

        await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_multiplexer != null)
            {
                return _multiplexer;
            }

            _logger.LogInformation("Initializing Redis connection asynchronously...");

            _multiplexer = await ConnectionMultiplexer.ConnectAsync(_options).ConfigureAwait(false);

            _multiplexer.ConnectionRestored += (sender, args) =>
                _logger.LogInformation("Redis connection restored. Endpoint: {Endpoint}", args.EndPoint);

            _multiplexer.ConnectionFailed += (sender, args) =>
            {
                if (args.Exception is null)
                {
                    _logger.LogWarning("Redis connection failed. Endpoint: {Endpoint}", args.EndPoint);
                }
                else
                {
                    _logger.LogWarning(args.Exception, "Redis connection failed. Endpoint: {Endpoint}", args.EndPoint);
                }
            };

            return _multiplexer;
        }
        finally
        {
            _connectionLock.Release();
        }
    }
#pragma warning restore CA1508

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _connectionLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _disposed = true;
            if (_multiplexer != null)
            {
                await _multiplexer.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _connectionLock.Release();
            _connectionLock.Dispose();
        }
    }
}
