using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.DPoP;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Benchmarks;

[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class DpopValidatorBenchmark : IDisposable
{
    private bool _disposed;
    private ECDsa? _ecdsa;
    private FastInMemoryJtiCache? _replayCache;
    private DpopValidationRequest? _request;
    private DpopProofValidator? _validator;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _ecdsa?.Dispose();
        }

        _disposed = true;
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "benchmark-key" };

        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        var jwkObject = new Dictionary<string, object>
        {
            ["kty"] = jwk.Kty!,
            ["crv"] = jwk.Crv!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var proof = CreateDpopProof(securityKey, jwkObject);

        _replayCache = new FastInMemoryJtiCache();

        var options = Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 300,
            AllowedClockSkewSeconds = 60,
            AllowedAlgorithms = [SecurityAlgorithms.EcdsaSha256]
        });

        _validator = new DpopProofValidator(_replayCache, options);
        _request = new DpopValidationRequest(proof, "POST", new Uri("https://api.sentinel.io/v1/auth"));
    }

    [IterationCleanup]
    public void IterationCleanup()
    {
        _replayCache?.Clear();
    }

    [Benchmark(Description = "DPoP Proof Cryptographic Validation")]
    public async Task<SecurityResult<DpopValidationSuccess>> ValidateDpopProof()
    {
        return await _validator!.ValidateAsync(_request!, CancellationToken.None);
    }

    private static string CreateDpopProof(ECDsaSecurityKey securityKey, Dictionary<string, object> jwkObject)
    {
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "POST",
                ["htu"] = "https://api.sentinel.io/v1/auth",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };
        return handler.CreateToken(descriptor);
    }

    private sealed class FastInMemoryJtiCache : IJtiReplayCache
    {
        private readonly HashSet<string> _jtis = new(StringComparer.Ordinal);

        public Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_jtis.Add(jti));
        }

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public void Clear() => _jtis.Clear();
    }
}
