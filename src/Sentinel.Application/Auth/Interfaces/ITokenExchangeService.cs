using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.Auth.Interfaces;

public interface ITokenExchangeService
{
    Task<TokenExchangeResult?> ExchangeExternalTokenAsync(string externalToken, string providerName, string dpopProof, CancellationToken ct);
}
