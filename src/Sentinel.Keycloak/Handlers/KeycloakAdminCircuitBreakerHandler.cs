using System.Net;
using System.Net.Http.Headers;

namespace Sentinel.Keycloak.Handlers;

internal sealed class KeycloakAdminCircuitBreakerState(TimeProvider? timeProvider = null)
{
    private static readonly TimeSpan BreakDuration = TimeSpan.FromSeconds(30);
    private readonly object _sync = new();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    private int _consecutiveFailures;
    private DateTimeOffset? _openUntil;

    public bool IsOpen(out TimeSpan retryAfter)
    {
        lock (_sync)
        {
            var now = _timeProvider.GetUtcNow();
            if (_openUntil is { } openUntil && openUntil > now)
            {
                retryAfter = openUntil - now;
                return true;
            }

            _openUntil = null;
            retryAfter = TimeSpan.Zero;
            return false;
        }
    }

    public bool RecordFailure(int failureThreshold)
    {
        lock (_sync)
        {
            _consecutiveFailures++;
            if (_consecutiveFailures < failureThreshold)
            {
                return false;
            }

            _consecutiveFailures = 0;
            _openUntil = _timeProvider.GetUtcNow().Add(BreakDuration);
            return true;
        }
    }

    public void RecordSuccess()
    {
        lock (_sync)
        {
            _consecutiveFailures = 0;
            _openUntil = null;
        }
    }
}

internal sealed class KeycloakAdminCircuitBreakerHandler(
    KeycloakAdminCircuitBreakerState state,
    ILogger<KeycloakAdminCircuitBreakerHandler> logger) : DelegatingHandler
{
    private const int FailureThreshold = 5;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (state.IsOpen(out var retryAfter))
        {
            var shortCircuitResponse = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                RequestMessage = request,
                ReasonPhrase = "Keycloak admin circuit is open"
            };

            var safeRetryAfter = retryAfter <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : retryAfter;
            shortCircuitResponse.Headers.RetryAfter = new RetryConditionHeaderValue(safeRetryAfter);

            logger.LogWarning("Keycloak admin circuit open. Short-circuiting request for {Method} {Uri}.",
                request.Method,
                request.RequestUri);

            return shortCircuitResponse;
        }

        try
        {
            var response = await base.SendAsync(request, cancellationToken);

            if (IsTransientFailure(response.StatusCode))
            {
                if (state.RecordFailure(FailureThreshold))
                {
                    logger.LogWarning(
                        "Keycloak admin circuit opened after repeated transient failures. Latest status: {StatusCode}.",
                        (int)response.StatusCode);
                }
            }
            else
            {
                state.RecordSuccess();
            }

            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            if (state.RecordFailure(FailureThreshold))
            {
                logger.LogWarning(
                    "Keycloak admin circuit opened after repeated request timeouts/cancellations.");
            }

            throw;
        }
        catch (HttpRequestException ex)
        {
            if (state.RecordFailure(FailureThreshold))
            {
                logger.LogWarning(ex,
                    "Keycloak admin circuit opened after repeated transport failures.");
            }

            throw;
        }
    }

    private static bool IsTransientFailure(HttpStatusCode statusCode)
    {
        return statusCode == HttpStatusCode.RequestTimeout
               || statusCode == HttpStatusCode.TooManyRequests
               || (int)statusCode >= 500;
    }
}
