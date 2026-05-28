using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.SdJwt;

namespace Sentinel.Benchmarks;

[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class SdJwtPresenterBenchmark : IDisposable
{
    private bool _disposed;
    private ECDsa? _holderKey;
    private ECDsa? _issuerKey;
    private ECDsaSecurityKey? _issuerSecurityKey;
    private string? _presentation;
    private SdJwtPresenter? _presenter;

    [Params(1, 10, 50)] public int DisclosuresCount { get; set; }

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
            _holderKey?.Dispose();
            _issuerKey?.Dispose();
        }

        _disposed = true;
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var holderJwk = CreateEcJwkObject(_holderKey);
        var holderJkt = ComputeEcThumbprint(holderJwk);

        _issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _issuerSecurityKey = new ECDsaSecurityKey(_issuerKey) { KeyId = "benchmark-issuer-key" };

        var disclosuresList = new List<string>();
        var digestsList = new List<string>();

        for (var i = 0; i < DisclosuresCount; i++)
        {
            var disclosure = CreateDisclosure($"salt-{i}", $"claim_{i}", $"value_{i}");
            disclosuresList.Add(disclosure);
            digestsList.Add(ComputeDisclosureDigest(disclosure));
        }

        var issuerJwt = CreateIssuerJwt(digestsList.ToArray(), holderJkt, _issuerSecurityKey);
        var kbJwt = CreateKeyBindingJwt(_holderKey, holderJwk, issuerJwt, disclosuresList.ToArray(), "sentinel-api");

        _presentation = $"{issuerJwt}~{string.Join("~", disclosuresList)}~{kbJwt}";
        _presenter = new SdJwtPresenter(new FakeTokenValidator(), new SdJwtVerificationOptions());
    }


    [Benchmark(Description = "SD-JWT Presentation Verification & Claims Materialization")]
    public async Task<SdJwtVerificationResult> VerifyPresentation()
    {
        return await _presenter!.VerifyPresentationAsync(_presentation!, "sentinel-api", null, CancellationToken.None);
    }

    private static string CreateIssuerJwt(string[] disclosureDigests, string holderJkt, SecurityKey issuerKey)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "sdjwt-user",
                ["_sd"] = disclosureDigests,
                ["_sd_alg"] = "sha-256",
                ["cnf"] = new Dictionary<string, string> { ["jkt"] = holderJkt }
            },
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(issuerKey, SecurityAlgorithms.EcdsaSha256)
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateKeyBindingJwt(ECDsa holderKey, Dictionary<string, string> holderJwk, string issuerJwt,
        string[] disclosures, string audience)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["sd_hash"] = ComputeSdHash(issuerJwt, disclosures)
            },
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials =
                new SigningCredentials(new ECDsaSecurityKey(holderKey), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = holderJwk }
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string CreateDisclosure(string salt, string claimName, string claimValue)
    {
        var json = JsonSerializer.Serialize(new object[] { salt, claimName, claimValue });
        return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string disclosure) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

    private static string ComputeSdHash(string issuerJwt, string[] disclosures) =>
        Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes($"{issuerJwt}~{string.Join("~", disclosures)}")));

    private static Dictionary<string, string> CreateEcJwkObject(ECDsa key)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(key));
        return new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwk) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { crv = jwk["crv"], kty = jwk["kty"], x = jwk["x"], y = jwk["y"] }))));

    private sealed class FakeTokenValidator : ISdJwtTokenValidator
    {
        private static readonly JsonWebTokenHandler TokenHandler = new();

        public Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(string issuerJwt,
            string expectedAudience, CancellationToken cancellationToken = default) =>
            Task.FromResult(SdJwtIssuerTokenValidationResult.Success(TokenHandler.ReadJsonWebToken(issuerJwt)));
    }
}
