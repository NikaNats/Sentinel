using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Sentinel.Security.Abstractions.Secrets;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Infrastructure.Cryptography;

public sealed class PrivacyKeyManager(ISecretProvider secretProvider, ILogger<PrivacyKeyManager> logger)
    : BackgroundService, IPrivacyKeyManager
{
    private readonly ILogger<PrivacyKeyManager> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly ISecretProvider _secretProvider =
        secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));

    private volatile byte[] _masterPepper = [];

    public ReadOnlySpan<byte> GetMasterPepper() => _masterPepper;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Fetching initial Master Pepper from Vault...");
        await RefreshKeyAsync(cancellationToken).ConfigureAwait(false);

        if (_masterPepper.Length != 32)
        {
            throw new CryptographicException(
                "CRITICAL: Sentinel API startup halted. Vault is unreachable or MasterPepper is invalid. Failing closed.");
        }

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken).ConfigureAwait(false);
                await RefreshKeyAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RefreshKeyAsync(CancellationToken ct)
    {
        try
        {
            var pepperBase64 = await _secretProvider.GetSecretAsync("sentinel/privacy", "MasterPepper", ct)
                .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(pepperBase64))
            {
                _logger.LogCritical("'MasterPepper' not found in Vault.");
                return;
            }

            var newPepper = Convert.FromBase64String(pepperBase64);
            if (newPepper.Length < 32)
            {
                _logger.LogCritical("MasterPepper must be at least 256 bits (32 bytes).");
                return;
            }

            _masterPepper = newPepper;
            _logger.LogInformation("Privacy Master Pepper successfully updated from Vault.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex,
                "Vault connection error during key refresh. Old Master Pepper remains active (Fail-Safe).");
        }
    }
}
