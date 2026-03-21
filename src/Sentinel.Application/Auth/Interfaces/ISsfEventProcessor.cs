using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface ISsfEventProcessor
{
    Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct);
}
