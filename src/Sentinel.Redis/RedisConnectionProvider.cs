namespace Sentinel.Redis;

/// <summary>
///     Thread-safe asynchronous connection provider for Redis.
///     Uses double-check locking pattern to ensure:
///     - Only one connection multiplexer instance is created
///     - No thundering herd of concurrent connection attempts during startup
///     - Graceful background reconnection (AbortOnConnectFail = false)
///     - Clean async/await semantics (no blocking thread pool threads)
/// </summary>
internal sealed class RedisConnectionProvider : IRedisConnectionProvider
{
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private readonly ILogger<RedisConnectionProvider> _logger;
    private readonly ConfigurationOptions _options;
    private bool _disposed; // ✅ FIX: Explicit disposal state to prevent race conditions
    private ConnectionMultiplexer? _multiplexer;

    public RedisConnectionProvider(RedisOptions redisOptions, ILogger<RedisConnectionProvider> logger)
    {
        _logger = logger;

        _options = ConfigurationOptions.Parse(redisOptions.EndPoint ?? "localhost:6379");
        _options.Ssl = redisOptions.UseSsl;
        _options.Password = redisOptions.Password;

        // CRITICAL: Prevents the multiplexer from throwing on transient network partitions.
        // With this set to false, StackExchange.Redis manages background reconnections natively.
        _options.AbortOnConnectFail = false;
        _options.ConnectRetry = 5;
        _options.ConnectTimeout = redisOptions.SyncTimeout;
        _options.AsyncTimeout = redisOptions.SyncTimeout; // Align async timeout
    }

    /// <summary>
    ///     Asynchronously retrieves the connection multiplexer.
    ///     Fast path (connection already exists): Returns immediately.
    ///     Slow path (first call): Acquires lock, establishes connection, registers reconnect handlers.
    /// </summary>
#pragma warning disable CA1508 // The second null check after lock is valid in double-check locking pattern
    public async ValueTask<IConnectionMultiplexer> GetConnectionAsync(CancellationToken cancellationToken = default)
    {
        // ✅ FIX: Check disposal state to prevent zombie connections after disposal
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Fast path: connection already exists
        if (_multiplexer != null)
        {
            return _multiplexer;
        }

        // Acquire lock to ensure only one thread initiates connection
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            // ✅ FIX: Re-check disposal state after acquiring lock
            ObjectDisposedException.ThrowIf(_disposed, this);
            // Double-check locking pattern: another thread may have initialized while we waited
            if (_multiplexer != null)
            {
                return _multiplexer;
            }

            _logger.LogInformation("Initializing Redis connection asynchronously...");

            _multiplexer = await ConnectionMultiplexer.ConnectAsync(_options);

            // Register handlers for operational observability
            _multiplexer.ConnectionRestored += (sender, args) =>
                _logger.LogInformation("Redis connection restored. Endpoint: {Endpoint}", args.EndPoint);

            // ✅ FIX: Safely handle nullable Exception in event args
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

    /// <summary>
    ///     Gracefully disposes the connection and internal synchronization primitive.
    ///     ✅ FIX: Acquire lock during disposal to safely block incoming GetConnectionAsync requests.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        // ✅ FIX: Acquire the lock during disposal to safe block incoming GetConnectionAsync requests
        await _connectionLock.WaitAsync();
        try
        {
            _disposed = true;
            if (_multiplexer != null)
            {
                await _multiplexer.DisposeAsync();
            }
        }
        finally
        {
            _connectionLock.Release();
            _connectionLock.Dispose();
        }
    }
}
