// Test infrastructure - suppress CA warnings that are not relevant for test code
#pragma warning disable CA1024 // Use properties where appropriate
#pragma warning disable CA1031 // Do not catch general exception types
#pragma warning disable CA2000 // Dispose objects before losing scope

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Integration.Cryptography;

/// <summary>
///     In-process HTTP test server serving a rotating JWKS endpoint and
///     OIDC discovery document. Used to verify JWKS key rotation behavior
///     without external dependencies.
/// </summary>
public sealed class RotatingJwksServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _serverTask;
    private readonly object _lock = new();

    private readonly string _issuer;
    private readonly Dictionary<string, (ECDsaSecurityKey Key, DateTime NotBefore)> _keys = new();
    private string _activeKid = "key-1";

    public RotatingJwksServer(int port = 0)
    {
        _listener = new HttpListener();
        var actualPort = port == 0 ? GetFreePort() : port;
        var baseUrl = $"http://127.0.0.1:{actualPort}/";
        _listener.Prefixes.Add(baseUrl);
        _listener.Start();

        _issuer = baseUrl.TrimEnd('/');
        _serverTask = Task.Run(ProcessRequestsAsync, _cts.Token);

        // Initialize with one key
        AddKey("key-1");
    }

    public Uri BaseUrl => new(_listener.Prefixes.First().TrimEnd('/'));

    public Uri JwksUrl => new(BaseUrl, ".well-known/jwks.json");

    public Uri MetadataUrl => new(BaseUrl, ".well-known/openid-configuration");

    public string Issuer => _issuer;

    public string ActiveKid => _activeKid;

    public IEnumerable<SecurityKey> GetAllKeys()
    {
        lock (_lock)
        {
            return _keys.Values.Select(k => k.Key).ToList();
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _keys.Clear();
            _activeKid = "key-1";
            AddKey("key-1");
        }
    }

    public void AddKey(string kid)
    {
        lock (_lock)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            try
            {
                var key = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
                _keys[kid] = (key, DateTime.UtcNow);
            }
#pragma warning disable CA2000
            catch
            {
                ecdsa.Dispose();
                throw;
            }
#pragma warning restore CA2000
        }
    }

    public void SetActiveKey(string kid)
    {
        lock (_lock)
        {
            if (!_keys.ContainsKey(kid))
            {
                throw new InvalidOperationException($"Key '{kid}' does not exist. Call AddKey first.");
            }
            _activeKid = kid;
        }
    }

    public void RemoveKey(string kid)
    {
        lock (_lock)
        {
            _keys.Remove(kid);
            if (_activeKid == kid && _keys.Count > 0)
            {
                _activeKid = _keys.Keys.First();
            }
        }
    }

    public ECDsaSecurityKey GetActiveKey()
    {
        lock (_lock)
        {
            return _keys[_activeKid].Key;
        }
    }

    public string MintToken(string? kid = null, TimeSpan? lifetime = null)
    {
        var activeKid = kid ?? _activeKid;
        var key = _keys[activeKid].Key;

        var handler = new JsonWebTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var exp = now.Add(lifetime ?? TimeSpan.FromMinutes(5));

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = Guid.NewGuid().ToString(),
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = exp.ToUnixTimeSeconds(),
            ["acr"] = "acr3",
            ["scope"] = "profile"
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = "sentinel-api",
            Claims = claims,
            Expires = exp.UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private async Task ProcessRequestsAsync()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            HttpListenerContext? ctx = null;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                _ = Task.Run(() => HandleRequest(ctx), _cts.Token);
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (HttpListenerException)
            {
                break;
            }
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        try
        {
            var path = ctx.Request.Url?.AbsolutePath ?? "/";

            if (path.Equals("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
            {
                var metadata = new
                {
                    issuer = _issuer,
                    jwks_uri = JwksUrl.ToString(),
                    authorization_endpoint = $"{_issuer}/protocol/openid-connect/auth",
                    token_endpoint = $"{_issuer}/protocol/openid-connect/token",
                    userinfo_endpoint = $"{_issuer}/protocol/openid-connect/userinfo",
                    end_session_endpoint = $"{_issuer}/protocol/openid-connect/logout"
                };
                RespondJson(ctx, metadata);
            }
            else if (path.Equals("/.well-known/jwks.json", StringComparison.OrdinalIgnoreCase))
            {
                lock (_lock)
                {
                    var jwks = new
                    {
                        keys = _keys.Values.Select(k => new JsonWebKey
                        {
                            Kty = "EC",
                            Crv = "P-256",
                            X = Base64UrlEncoder.Encode(k.Key.ECDsa.ExportParameters(false).Q.X!),
                            Y = Base64UrlEncoder.Encode(k.Key.ECDsa.ExportParameters(false).Q.Y!),
                            Kid = k.Key.KeyId,
                            Alg = "ES256",
                            Use = "sig"
                        }).ToArray()
                    };
                    RespondJson(ctx, jwks);
                }
            }
            else
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        }
#pragma warning disable CA1031
        catch
        {
            try { ctx.Response.StatusCode = 500; } catch { }
            finally { ctx.Response.Close(); }
        }
#pragma warning restore CA1031
    }

    private static void RespondJson(HttpListenerContext ctx, object payload)
    {
        var json = JsonSerializer.Serialize(payload);
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.OutputStream.Write(bytes);
        ctx.Response.Close();
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        _listener.Close();
#pragma warning disable CA1031
        try { _serverTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
#pragma warning restore CA1031
        _cts.Dispose();
    }
}