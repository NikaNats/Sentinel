using Microsoft.Extensions.Hosting;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Session;

namespace Sentinel.EntityFrameworkCore.Services;

/// <summary>
///     Background service responsible for cleaning up expired entries from security caches.
///     Prevents database disk exhaustion DoS attacks by periodically removing stale JTI, nonce, and session entries.
///     <remarks>
///         This service runs every 15 minutes to ensure timely cleanup of expired security cache entries.
///         Failures in cleanup operations are logged but do not prevent the application from continuing.
///         All cache implementations follow fail-closed semantics: cleanup failures do not affect query operations.
///     </remarks>
/// </summary>
internal sealed class SecurityCacheCleanupService : BackgroundService
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(15);
    private readonly IJtiReplayCache _jtiCache;

    private readonly ILogger<SecurityCacheCleanupService> _logger;
    private readonly IDpopNonceStore _nonceStore;
    private readonly ISessionBlacklistCache _sessionBlacklist;

    public SecurityCacheCleanupService(
        ILogger<SecurityCacheCleanupService> logger,
        IJtiReplayCache jtiCache,
        IDpopNonceStore nonceStore,
        ISessionBlacklistCache sessionBlacklist)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _jtiCache = jtiCache ?? throw new ArgumentNullException(nameof(jtiCache));
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        _sessionBlacklist = sessionBlacklist ?? throw new ArgumentNullException(nameof(sessionBlacklist));
    }

    /// <summary>
    ///     Executes the background cleanup task every 15 minutes.
    ///     Errors in individual cache cleanup operations do not cascade; all cleanup tasks are attempted regardless.
    /// </summary>
#pragma warning disable CA1031 // Do not catch general exception types
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SecurityCacheCleanupService started. Running cleanup every {Interval} minutes.",
            CleanupInterval.TotalMinutes);

        // Give the application startup time to complete before beginning cleanup operations.
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _logger.LogDebug("Starting security cache cleanup cycle");

                // Attempt cleanup for all three caches independently.
                // If one fails, the others still execute (fail-closed semantics).
                var jtiTask = CleanupCacheAsync(
                    "JTI replay cache",
                    () => _jtiCache.CleanupExpiredAsync(stoppingToken),
                    stoppingToken);

                var nonceTask = CleanupCacheAsync(
                    "DPoP nonce store",
                    () => _nonceStore.CleanupExpiredAsync(stoppingToken),
                    stoppingToken);

                var sessionTask = CleanupCacheAsync(
                    "Session blacklist",
                    () => _sessionBlacklist.CleanupExpiredAsync(stoppingToken),
                    stoppingToken);

                await Task.WhenAll(jtiTask, nonceTask, sessionTask);

                _logger.LogDebug("Security cache cleanup cycle completed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error during security cache cleanup cycle (operation will retry in {Interval} minutes)",
                    CleanupInterval.TotalMinutes);
            }

            // Wait for the specified interval before the next cleanup cycle.
            try
            {
                await Task.Delay(CleanupInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("SecurityCacheCleanupService stopping");
                throw;
            }
        }
    }
#pragma warning restore CA1031

    /// <summary>
    ///     Safely executes a cache cleanup operation with error handling and logging.
    /// </summary>
#pragma warning disable CA1031 // Do not catch general exception types
    private async Task CleanupCacheAsync(
        string cacheName,
        Func<Task> cleanupOperation,
        CancellationToken cancellationToken)
    {
        try
        {
            await cleanupOperation();
            _logger.LogDebug("{CacheName} cleanup completed successfully", cacheName);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("{CacheName} cleanup cancelled", cacheName);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "{CacheName} cleanup operation failed; will retry in next cycle", cacheName);
            // Fail-closed: Don't rethrow; the next cycle will retry.
        }
    }
#pragma warning restore CA1031
}
