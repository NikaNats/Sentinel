// Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
//
// sentinel-dast-auth-proxy - TEST-ONLY RFC 9449 DPoP client-side signing proxy.
//
// Purpose: OWASP ZAP / Nuclei are DPoP-unaware. Because Sentinel's FAPI 2.0
// stack (PAR + PKCE + DPoP + jti replay cache + nonce rotation) rejects every
// request without a valid ES256 DPoP Proof bound to the JWT's cnf.jkt, a
// vanilla scanner only ever sees 401s. THIS COMPONENT fixes that WITHOUT
// relaxing a single Sentinel control: it forwards the scanner's request
// verbatim and performs, per request:
//   1. fresh DPoP-bound access token (client_credentials + DPoP proof) - the
//      jti replay cache consumes each access-token jti ONCE, so tokens are
//      NEVER cached across requests;
//   2. RFC 9449 nonce state machine (challenge -> retry, rotation on every
//      response's DPoP-Nonce header);
//   3. RFC 9449 ath binding (SHA-256 of the access token);
//   4. Idempotency-Key injection for mutating endpoints (RFC 9110,
//      Sentinel's IdempotencyFilter);
//   5. a global rate limiter so scanners stay under ConcurrencyLimiter
//      policies (429s are expected behavior for over-speedy scans).
//
// NEVER ship this binary; NEVER point it at a production realm. It lives in
// the ephemeral DAST stack only (see infra/dast/docker-compose.dast.yml).

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
_ = builder.Services.AddSingleton<DpopSigningClient>();
var app = builder.Build();

var config = app.Configuration;
var target = config["Dast:Target"] ?? throw new InvalidOperationException("Dast:Target is required");
var rps = double.Parse(config["Dast:RequestsPerSecond"] ?? "2", CultureInfo.InvariantCulture);
var caPath = config["Keycloak:TrustedCaPath"] ?? throw new InvalidOperationException("Keycloak:TrustedCaPath is required");

if (!File.Exists(caPath))
{
    // Fail closed: never fall back to skipping validation (Constitution §III.4).
    throw new InvalidOperationException($"CA bundle not found at '{caPath}'. Refusing to proxy without TLS trust.");
}

// The handler is intentionally process-lifetime (shared by all requests);
// CA2000's reference-counting cannot see it escape to DI/disposal scope.
// NOTE: this is safe for the Minimal API lifetime ONLY. If this proxy is ever
// converted to a hosted service or the handler enters DI (AddHttpClient etc.),
// it MUST be disposed with the host to avoid socket exhaustion.
#pragma warning disable CA2000
var tlsHandler = CreateTlsHandler(caPath);
#pragma warning restore CA2000
var dpop = app.Services.GetRequiredService<DpopSigningClient>();

app.MapGet("/proxy-health", () => Results.Text("ok"));

// Catch-all: sign and forward every scanner request through the REAL pipeline.
app.Map("/{**catchAll}", async (HttpContext ctx, CancellationToken ct) =>
{
    await dpop.ThrottleAsync(rps, ct);

    var method = ctx.Request.Method;
    var url = new Uri(new Uri(target), ctx.Request.Path + ctx.Request.QueryString);

    using var upstream = new HttpClient(tlsHandler, disposeHandler: false);

    var (accessToken, _) = await dpop.AcquireBoundTokenAsync(tlsHandler, ct);

    // Read the body once so a nonce-challenge retry can re-send it.
    byte[] bodyBytes;
    await using (var ms = new MemoryStream())
    {
        await ctx.Request.Body.CopyToAsync(ms, ct);
        bodyBytes = ms.ToArray();
    }

    HttpStatusCode status;
    HttpResponseMessage res;
    var attempts = 0;
    do
    {
        var proof = dpop.CreateProof(method, url, accessToken, dpop.CurrentNonce);
        using var req = BuildForwardRequest(method, url, ctx, bodyBytes, accessToken, proof);

        res = await upstream.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

        if (res.Headers.TryGetValues("DPoP-Nonce", out var nonces))
        {
            dpop.RememberNonce(nonces.First());
        }

        // RFC 9449 §4.3: one automatic nonce-challenge retry.
        var challenge = res.Headers.WwwAuthenticate.ToString();
        status = res.StatusCode;
        if (status != HttpStatusCode.Unauthorized || !challenge.Contains("use_dpop_nonce", StringComparison.OrdinalIgnoreCase))
        {
            break;
        }

        attempts++;
    } while (attempts < 2 && dpop.CurrentNonce is not null);

    ctx.Response.StatusCode = (int)status;
    foreach (var h in res.Headers)
    {
        // HttpClient de-chunks the upstream body, so relaying the upstream
        // Transfer-Encoding header would make clients re-parse the already
        // decoded bytes as chunk framing (e.g. curl: "chunk hex-length char
        // not a hex digit"). Let Kestrel re-frame the body; drop Connection
        // so it can manage keep-alive itself.
        if (h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
            || h.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        ctx.Response.Headers[h.Key] = h.Value.ToArray();
    }

    foreach (var h in res.Content.Headers)
    {
        ctx.Response.Headers[h.Key] = h.Value.ToArray();
    }

    await res.Content.CopyToAsync(ctx.Response.Body, ct);
});

app.Run();

// Builds the forwarded request: copies scanner headers (minus the ones the
// proxy reassigns), injects Idempotency-Key on mutating methods (RFC 9110),
// and attaches the fresh DPoP-bound Authorization + Proof.
static HttpRequestMessage BuildForwardRequest(
    string method,
    Uri url,
    HttpContext ctx,
    byte[] bodyBytes,
    string accessToken,
    string proof)
{
    var req = new HttpRequestMessage(new HttpMethod(method), url)
    {
        Content = bodyBytes.Length == 0 ? null : new ByteArrayContent(bodyBytes)
    };

    foreach (var h in ctx.Request.Headers.Where(h =>
        !h.Key.StartsWith("Authorization", StringComparison.OrdinalIgnoreCase) &&
        !h.Key.StartsWith("DPoP", StringComparison.OrdinalIgnoreCase) &&
        !h.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) &&
        !h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) &&
        !h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)))
    {
        _ = req.Headers.TryAddWithoutValidation(h.Key, h.Value.ToArray());
    }

    // Mutating endpoints demand Idempotency-Key (IdempotencyFilter: RFC 9110).
    if (method is "POST" or "PUT" or "PATCH" or "DELETE" && !req.Headers.Contains("Idempotency-Key"))
    {
        req.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString("N"));
    }

    req.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
    req.Headers.Add("DPoP", proof);

    if (req.Content is not null)
    {
        var contentType = ctx.Request.ContentType ?? "application/json";
        req.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
    }

    return req;
}

// TLS handler verifying the Sentinel private PKI (infra/certs/ca.crt) through
// a custom root trust - the exact pattern the sample application uses. Not a
// no-op: anything the custom CA cannot verify is REJECTED (fail closed).
static SocketsHttpHandler CreateTlsHandler(string caPath)
{
    // Single-arg CreateFromPem (cert-only) is REQUIRED here: CreateFromPemFile
    // demands a private key matching the cert and throws at startup when given
    // a CA bundle (certificate-only PEM) - verified live under the Linux
    // container (exit 139).
    //
    // Keep caCert UNDISPOSED on purpose: X509Chain ("CustomTrustStore") throws
    // "A null or disposed certificate was present in CustomTrustStore" if this
    // cert is disposed while the handler is still serving TLS handshakes
    // (verified live: 500s on every forwarded request). It is process-lifetime
    // like `handler`, held alive by the validation callback closure.
    // caCert is process-lifetime like `handler` (intentionally undisposed).
#pragma warning disable CA2000
    var caCert = X509Certificate2.CreateFromPem(File.ReadAllText(caPath));
#pragma warning restore CA2000

    var handler = new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        SslOptions = new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None)
                {
                    return true;
                }

                if (cert is not X509Certificate2 xc)
                {
                    return false;
                }

                using var customChain = new X509Chain();
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                customChain.ChainPolicy.DisableCertificateDownloads = true;
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.CustomTrustStore.Add(caCert);

                return customChain.Build(xc);
            }
        }
    };

    return handler;
}

/// <summary>
///     RFC 9449 client state machine: per-run ephemeral ES256 key, DPoP-Nonce
///     rotation, access-token binding (ath), and global scan throttling.
/// </summary>
sealed class DpopSigningClient(IConfiguration cfg) : IDisposable
{
    private const string TokenType = "dpop+jwt";

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly SemaphoreSlim _throttle = new(1, 1);
    private string? _nonce;

    public void Dispose()
    {
        _key.Dispose();
        _throttle.Dispose();
    }

    /// <summary>Latest nonce from the token/API (rotated on every response).</summary>
    public string? CurrentNonce => Volatile.Read(ref _nonce);

    public void RememberNonce(string nonce) => Volatile.Write(ref _nonce, nonce);

    public async Task ThrottleAsync(double rps, CancellationToken ct)
    {
        await _throttle.WaitAsync(ct);
        try
        {
            var interval = TimeSpan.FromSeconds(1.0 / Math.Max(0.1, rps));
            await Task.Delay(interval, ct);
        }
        finally
        {
            _ = _throttle.Release();
        }
    }

    /// <summary>
    ///     Client-credentials + DPoP proof against Keycloak. Handles the token
    ///     endpoint's own use_dpop_nonce challenge once, then returns a fresh
    ///     DPoP-bound access token. Never caches tokens - the Sentinel jti
    ///     replay cache consumes each access-token jti exactly once.
    /// </summary>
    public async Task<(string Token, string? Nonce)> AcquireBoundTokenAsync(SocketsHttpHandler tlsHandler, CancellationToken ct)
    {
        var endpoint = new Uri(cfg["Keycloak:TokenEndpoint"]!);
        var clientSecret = cfg["Keycloak:ClientSecret"]!;
        using var http = new HttpClient(tlsHandler, disposeHandler: false);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = cfg["Keycloak:ClientId"]!,
                    ["client_secret"] = clientSecret,
                    ["scope"] = "profile documents:read documents:write"
                })
            };

            req.Headers.Add("DPoP", CreateProof("POST", endpoint, null, CurrentNonce));

            using var res = await http.SendAsync(req, ct);

            if (res.Headers.TryGetValues("DPoP-Nonce", out var nonces))
            {
                RememberNonce(nonces.First());
            }

            if (!res.IsSuccessStatusCode && !res.Headers.WwwAuthenticate.ToString().Contains("use_dpop_nonce", StringComparison.OrdinalIgnoreCase))
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException($"Token endpoint {(int)res.StatusCode}: {body}");
            }

            if (res.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                var token = doc.RootElement.GetProperty("access_token").GetString()!;
                return (token, CurrentNonce);
            }
        }

        throw new InvalidOperationException("DPoP nonce retry exhausted on the token endpoint");
    }

    /// <summary>
    ///    RFC 9449 DPoP Proof, ES256: typ=dpop+jwt, embedded public JWK,
    ///    jti/htm/htu/iat/nonce/ath claims, signed with the run-run key.
    /// </summary>
    public string CreateProof(string method, Uri htu, string? accessToken, string? nonce)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(_key));
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = $"{htu.Scheme}://{htu.Authority}{htu.AbsolutePath}",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }

        if (accessToken is not null)
        {
            claims["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            TokenType = TokenType,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = jwk.Kty ?? "EC",
                    ["crv"] = jwk.Crv ?? "P-256",
                    ["x"] = jwk.X ?? string.Empty,
                    ["y"] = jwk.Y ?? string.Empty
                }
            }
        });
    }
}