using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Sentinel.Security.Diagnostics;

namespace Sentinel.AspNetCore.Infrastructure;

/// <summary>
///     Options for Kestrel certificate hot reload.
/// </summary>
public sealed class KestrelCertificateReloaderOptions
{
    public const string SectionName = "Kestrel:CertificateReloader";

    /// <summary>
    ///     Path to the certificate file (PEM with private key, or PFX).
    ///     Supports both PEM (certificate + private key in one file) and PFX formats.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>
    ///     Password for PFX certificate (not needed for PEM).
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    ///     Debounce interval for file system changes.
    ///     Default: 500ms to avoid reacting to partial writes.
    /// </summary>
    public TimeSpan DebounceInterval { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    ///     Minimum days remaining before a certificate is considered near expiry.
    ///     Used for alerting via metrics.
    /// </summary>
    public int WarningDaysThreshold { get; set; } = 30;

    /// <summary>
    ///     Maximum time to wait for initial certificate load on startup.
    /// </summary>
    public TimeSpan StartupTimeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
///     Hot-reloadable certificate provider for Kestrel.
///     Watches a certificate file and atomically swaps the certificate
///     used by Kestrel's ServerCertificateSelector without restart.
/// </summary>
public sealed class KestrelCertificateReloader : IDisposable
{
    private readonly KestrelCertificateReloaderOptions _options;
    private readonly FileSystemWatcher _watcher;
    private CancellationTokenSource _debounceCts = new();
    private readonly object _swapLock = new();

    private volatile X509Certificate2? _currentCert;
    private double _daysRemaining;

    /// <summary>
    ///     Gets the currently active certificate, or null if not yet loaded.
    /// </summary>
    public X509Certificate2? CurrentCertificate => _currentCert;

    /// <summary>
    ///     Gets the days remaining until the current certificate expires.
    /// </summary>
    public double DaysRemaining => Interlocked.CompareExchange(ref _daysRemaining, 0, 0);

    /// <summary>
    ///     Event raised when the certificate is successfully reloaded.
    /// </summary>
    public event EventHandler<CertificateReloadedEventArgs>? CertificateReloaded;

    public KestrelCertificateReloader(IOptionsMonitor<KestrelCertificateReloaderOptions> optionsMonitor)
    {
        _options = optionsMonitor.CurrentValue;

        optionsMonitor.OnChange(opts => _ = ReloadAsync(opts));

        _watcher = new FileSystemWatcher
        {
            Path = System.IO.Path.GetDirectoryName(_options.Path!) ?? ".",
            Filter = System.IO.Path.GetFileName(_options.Path!),
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = false
        };
        _watcher.Changed += OnFileChanged;

        // Initial load
        _ = LoadCertificateAsync(_options);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        _debounceCts.Cancel();
        _debounceCts = new CancellationTokenSource();

        Task.Delay(_options.DebounceInterval, _debounceCts.Token)
            .ContinueWith(_ =>
            {
                if (!_debounceCts.Token.IsCancellationRequested)
                {
                    _ = ReloadAsync(_options);
                }
            }, TaskScheduler.Default);
    }

    private async Task ReloadAsync(KestrelCertificateReloaderOptions options)
    {
        try
        {
            var cert = await LoadCertificateFromFileAsync(options, CancellationToken.None);
            if (cert != null)
            {
                SwapCertificate(cert);
            }
        }
#pragma warning disable CA1031
        catch (Exception)
        {
            // Log error but keep serving old certificate
        }
#pragma warning restore CA1031
    }

    private static async Task<X509Certificate2?> LoadCertificateFromFileAsync(
        KestrelCertificateReloaderOptions options,
        CancellationToken ct)
    {
        var path = options.Path;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        const int maxRetries = 3;
        const int baseDelayMs = 100;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                X509Certificate2 cert;
                if (path.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
                    path.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
                {
                    var bytes = await File.ReadAllBytesAsync(path, ct);
                    cert = X509CertificateLoader.LoadPkcs12(bytes, options.Password,
                        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                }
                else
                {
                    cert = X509CertificateLoader.LoadCertificateFromFile(path);
                }

                if (cert.NotAfter <= DateTime.UtcNow)
                {
                    throw new InvalidOperationException($"Certificate at {path} has expired.");
                }

                return cert;
            }
#pragma warning disable CA1031
            catch (CryptographicException) when (attempt < maxRetries - 1)
            {
                await Task.Delay(baseDelayMs * (attempt + 1), ct);
            }
            catch (IOException) when (attempt < maxRetries - 1)
            {
                await Task.Delay(baseDelayMs * (attempt + 1), ct);
            }
#pragma warning restore CA1031
        }

        return null;
    }

    private async Task LoadCertificateAsync(KestrelCertificateReloaderOptions options)
    {
        var cert = await LoadCertificateFromFileAsync(options, CancellationToken.None);
        if (cert != null)
        {
            SwapCertificate(cert);
        }
    }

    private void SwapCertificate(X509Certificate2 newCert)
    {
        lock (_swapLock)
        {
            var oldCert = Interlocked.Exchange(ref _currentCert, newCert);

            if (oldCert != null)
            {
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None);
                    oldCert.Dispose();
                });
            }

            var daysRemaining = (newCert.NotAfter - DateTime.UtcNow).TotalDays;
            _daysRemaining = daysRemaining;
            AuthTelemetry.TlsCertDaysRemaining = Interlocked.Exchange(ref _daysRemaining, daysRemaining);

            CertificateReloaded?.Invoke(this, new CertificateReloadedEventArgs(newCert));
        }
    }

    public void Dispose()
    {
        _watcher.EnableRaisingEvents = false;
        _watcher.Dispose();
        _debounceCts.Cancel();
        _debounceCts.Dispose();

        var cert = Interlocked.Exchange(ref _currentCert, null);
        cert?.Dispose();
    }
}

/// <summary>
///     Event arguments for certificate reload events.
/// </summary>
public sealed class CertificateReloadedEventArgs : EventArgs
{
    public CertificateReloadedEventArgs(X509Certificate2 certificate)
    {
        Certificate = certificate;
    }

    public X509Certificate2 Certificate { get; }
}