namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Centralized telemetry metrics and activities for Sentinel authentication and authorization events.
/// Native to the Security layer - can be used independently of any application infrastructure.
///
/// IMPORTANT LIFECYCLE NOTE:
/// Because Meter and ActivitySource are static, they must be registered with the OpenTelemetry SDK
/// during host startup (e.g., using AddMeter and AddSource in the OpenTelemetry configuration).
/// The OTel SDK's IHostedService will ensure they are properly flushed and disposed during an
/// application shutdown (SIGTERM), preventing the loss of critical security events in the final seconds
/// of operation (which may contain traces of exploits that caused the crash).
/// </summary>
public static class AuthTelemetry
{
    /// <summary>
    /// Activity source name for distributed tracing (OpenTelemetry).
    /// </summary>
    public const string SourceName = "Sentinel.Auth.Tracing";

    /// <summary>
    /// Meter name for metrics collection (OpenTelemetry).
    /// </summary>
    public const string MeterName = "Sentinel.Auth.Metrics";

    /// <summary>
    /// Activity source for creating spans (W3C Trace Context compatible).
    /// </summary>
    public static readonly ActivitySource Source = new(SourceName);

    /// <summary>
    /// Meter for recording authentication metrics (OpenTelemetry Metrics).
    /// </summary>
    public static readonly Meter Meter = new(MeterName);

    /// <summary>
    /// Counter: DPoP proof validation failures.
    /// </summary>
    public static readonly Counter<long> DpopFailures = Meter.CreateCounter<long>(
        "auth.dpop.failures",
        description: "Number of DPoP validation failures");

    /// <summary>
    /// Counter: Token replay attempts (JTI duplicates).
    /// </summary>
    public static readonly Counter<long> TokenReplays = Meter.CreateCounter<long>(
        "auth.jti.replays_total",
        description: "Number of token replay attempts detected");

    /// <summary>
    /// Counter: Successfully issued tokens.
    /// </summary>
    public static readonly Counter<long> TokenIssued = Meter.CreateCounter<long>(
        "auth.token.issued",
        description: "Number of issued tokens by assurance level");

    /// <summary>
    /// Histogram: Token validation latency in seconds.
    /// ✅ FIX: Renamed to remove _ms suffix; unit set to "s" strictly following OTel Semantic Conventions.
    /// Prometheus/OTLP require metrics to use seconds for duration measurements, not milliseconds.
    /// </summary>
    public static readonly Histogram<double> ValidationDuration = Meter.CreateHistogram<double>(
        "auth.token.validation.duration",
        unit: "s",
        description: "Duration of token validation in seconds");

    /// <summary>
    /// Counter: Redis degradation events triggering node-local replay protection.
    /// </summary>
    public static readonly Counter<long> RedisDegradedModeActivations = Meter.CreateCounter<long>(
        "auth.redis.degraded_mode_activations",
        description: "Number of transitions into node-local replay protection mode.");

    /// <summary>
    ///     Counter: Number of DPoP nonce mismatches, stale nonces, or failed compare-and-delete attempts.
    /// </summary>
    public static readonly Counter<long> DpopNonceMismatches = Meter.CreateCounter<long>(
        "auth.dpop.nonce_mismatch_total",
        description: "Number of DPoP nonce mismatch, stale presentation, or atomic consumption failure events.");

    /// <summary>
    ///     Counter: Number of idempotency lock acquisition contentions (IN_PROGRESS collisions or retries).
    /// </summary>
    public static readonly Counter<long> IdempotencyLockContentions = Meter.CreateCounter<long>(
        "auth.idempotency.lock_contention_total",
        description: "Number of idempotency lock acquisition contentions under concurrent load.");

    // ---------------------------------------------------------------------
    // Cryptographic & PKI lifecycle telemetry (Enterprise Cryptographic and
    // PKI Lifecycle Architecture, docs/CRYPTO_LIFECYCLE_RUNBOOK.md).
    //
    // Metric names follow OTel-style namespacing under `crypto.*`:
    //   - jwks.refresh_total:    JWKS refresh requested after kid-miss.
    //   - jwks.kid_miss_total:    signature-key-not-found events (kid label).
    //   - tls.cert_days_remaining: days until the served TLS certificate
    //     expires (observable gauge; provider updated by the cert reloader).
    //   - lazy_rewraps_total:     envelope ciphertexts re-encrypted under the
    //     active key during decryption (key_id label).
    //   - keyring.active_key_mismatch: decryptions whose envelope key differs
    //     from the configured active key (keyring rotation drift signal).
    // ---------------------------------------------------------------------

    /// <summary>
    ///     Counter: JWKS refresh requests triggered by a signature-key-not-found
    ///     (kid-miss) event during token validation.
    /// </summary>
    public static readonly Counter<long> JwksRefreshRequests = Meter.CreateCounter<long>(
        "crypto.jwks.refresh_total",
        description: "Number of JWKS configuration refresh requests after a signing key lookup miss.");

    /// <summary>
    ///     Counter: Signing key (kid) lookup misses during JWT signature validation.
    /// </summary>
    public static readonly Counter<long> JwksKidMisses = Meter.CreateCounter<long>(
        "crypto.jwks.kid_miss_total",
        description: "Number of JWT signature validations that failed to find the token signing key (kid).");

    /// <summary>
    ///     Observable gauge: days remaining until the currently served TLS
    ///     certificate expires. Updated by KestrelCertificateReloader on every
    ///     (re)load; a value crossing the alerting threshold indicates the
    ///     operator must renew the certificate.
    /// </summary>
    private static double s_tlsCertDaysRemaining;

    /// <summary>
    ///     Gets or sets the days remaining until the served TLS certificate
    ///     expires. The Kestrel certificate reloader updates this value on
    ///     every certificate (re)load; the observable gauge below reports it.
    /// </summary>
    public static double TlsCertDaysRemaining
    {
        get => Interlocked.CompareExchange(ref s_tlsCertDaysRemaining, 0, 0);
        set => Interlocked.Exchange(ref s_tlsCertDaysRemaining, value);
    }

    /// <summary>
    ///     Observable gauge: remaining certificate lifetime (days).
    /// </summary>
    public static readonly ObservableGauge<double> TlsCertDaysRemainingGauge = Meter.CreateObservableGauge<double>(
        "crypto.tls.cert_days_remaining",
        () => s_tlsCertDaysRemaining,
        unit: "days",
        description: "Days until the served TLS certificate expires.");

    /// <summary>
    ///     Counter: Envelope ciphertexts decrypted under a non-active key and
    ///     transparently re-encrypted (lazy re-wrap) under the active key.
    /// </summary>
    public static readonly Counter<long> LazyRewraps = Meter.CreateCounter<long>(
        "crypto.lazy_rewraps_total",
        description: "Number of envelope ciphertexts re-encrypted under the active key during decryption.");

    /// <summary>
    ///     Counter: Envelope decryptions whose keyring key differs from the
    ///     configured active key. A non-zero rate (summed by key_id) is the
    ///     rotation-drift alerting signal: either the keyring was rotated
    ///     without the active key being updated, or legacy data remains.
    /// </summary>
    public static readonly Counter<long> KeyRingActiveKeyMismatches = Meter.CreateCounter<long>(
        "crypto.keyring.active_key_mismatch",
        description: "Number of decryptions performed with a keyring key that differs from the active key.");
}
