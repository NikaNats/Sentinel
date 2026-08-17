using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using Sentinel.Tests.Shared;

namespace Sentinel.Tests.Integration.Observability;

/// <summary>
///     Layer 1 of the Dual-Layer Observability Validation Strategy: contract tests that pin
///     the security-telemetry contract of the running API - token replay MUST surface as
///     auth.jti.replays_total + a PII-safe TOKEN_REPLAY_ALERT log, DPoP failures MUST surface
///     as auth.dpop.failures - and every attempt MUST be timed (auth.token.validation.duration).
/// </summary>
[Collection("Sentinel Observability Contract")]
public sealed class ObservabilityContractTests(ObservabilityContractFactory factory)
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact]
    public async Task AccessTokenReplay_ConsumesJti_EmitsMetricAndPiiSafeSiemAlert()
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var requestUri = new Uri(client.BaseAddress!, "/v1/profile");
        var requestUrl = requestUri.ToString();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
        var jkt = ComputeEcThumbprint(jwkObject);

        var subject = Guid.NewGuid().ToString("N");
        var accessToken = TestTokenIssuer.MintAccessToken(jkt, subject: subject);
        var rawJti = new JsonWebToken(accessToken).GetPayloadValue<string>("jti");

        // Request 1: valid proof (no stored nonce yet) -> 200 + DPoP-Nonce rotation.
        var firstProof = CreateDpopProof(securityKey, jwkObject, Guid.NewGuid().ToString("N"), requestUrl, null);
        using var req1 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req1.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        req1.Headers.Add("DPoP", firstProof);
        req1.Headers.Add("X-Correlation-ID", correlationId);
        var res1 = await client.SendAsync(req1, CancellationToken.None);
        res1.StatusCode.Should().Be(HttpStatusCode.OK);
        res1.Headers.TryGetValues("DPoP-Nonce", out var nonceValues).Should().BeTrue("the API rotates DPoP nonces");
        var nonce = nonceValues!.First();

        // Request 2: SAME access token (jti replay), fresh proof jti, consumed nonce -> 401.
        var replayProof = CreateDpopProof(securityKey, jwkObject, Guid.NewGuid().ToString("N"), requestUrl, nonce);
        using var req2 = new HttpRequestMessage(HttpMethod.Get, requestUri);
        req2.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        req2.Headers.Add("DPoP", replayProof);
        req2.Headers.Add("X-Correlation-ID", correlationId);
        var res2 = await client.SendAsync(req2, CancellationToken.None);
        res2.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        factory.FlushTelemetryAsync();

        // Contract 1: the access-token jti replay is observable as auth.jti.replays_total.
        var replays = factory.Metrics.FirstOrDefault(m => m.Name == "auth.jti.replays_total");
        replays.Should().NotBeNull("the replayed access token MUST increment auth.jti.replays_total");
        replays!.MetricPoints.Sum(p => p.GetSumLong()).Should().Be(1, "exactly one access-token replay was attempted");

        // Contract 2: the SIEM alert is emitted as a structured Critical log with the
        // caller-supplied correlation id and privacy-preserving 64-hex hashes - never raw PII.
        var alert = factory.Logs.FirstOrDefault(l =>
            (l.Attributes ?? []).Any(a => a.Key == "{OriginalFormat}"
                && a.Value?.ToString()?.Contains("TOKEN_REPLAY_ALERT", StringComparison.Ordinal) == true));
        alert.Should().NotBeNull("the replay MUST emit the TOKEN_REPLAY_ALERT structured log");
        HasAttribute(alert.Attributes, "CorrelationId", correlationId).Should().BeTrue(
            "the caller-supplied correlation id MUST be propagated into the SIEM log");

        var alertText = string.Join(" ", (alert.Attributes ?? []).Select(a => a.Value?.ToString()));
        alertText.Should().NotContain(rawJti, "the raw jti MUST NOT leak into the SIEM log");
        alertText.Should().NotContain(subject, "the raw subject MUST NOT leak into the SIEM log");
        alertText.Should().NotContain("127.0.0.1", "the raw client IP MUST NOT leak into the SIEM log");
        Regex.Count(alertText, "[0-9A-F]{64}").Should().BeGreaterThanOrEqualTo(2,
            "jti and sub MUST be emitted as 64-hex privacy hashes");
    }

    [Fact]
    public async Task InvalidDpopProof_RecordsFailureMetricAndValidationDuration()
    {
        var requestUri = new Uri(client.BaseAddress!, "/v1/profile");
        var requestUrl = requestUri.ToString();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = Guid.NewGuid().ToString("N") };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);
        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };
        var jkt = ComputeEcThumbprint(jwkObject);
        var accessToken = TestTokenIssuer.MintAccessToken(jkt);

        // Validly signed proof bound to the WRONG URL: passes parse + signature checks,
        // fails RFC 9449 htu binding inside validator.ValidateAsync.
        var wrongUrl = new Uri(client.BaseAddress!, "/v1/other").ToString();
        var proof = CreateDpopProof(securityKey, jwkObject, Guid.NewGuid().ToString("N"), wrongUrl, null);

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", proof);
        var response = await client.SendAsync(request, CancellationToken.None);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        factory.FlushTelemetryAsync();

        var failures = factory.Metrics.FirstOrDefault(m => m.Name == "auth.dpop.failures");
        failures.Should().NotBeNull("the failed DPoP attempt MUST increment auth.dpop.failures");
        failures!.MetricPoints.Sum(p => p.GetSumLong()).Should().BeGreaterThanOrEqualTo(1);
        failures.MetricPoints.Should().Contain(
            p => HasTag(p.Tags, "reason", "htu_mismatch"),
            "the failure reason MUST be attributed (htu_mismatch)");

        var duration = factory.Metrics.FirstOrDefault(m => m.Name == "auth.token.validation.duration");
        duration.Should().NotBeNull("every full validation attempt MUST be timed");
        duration!.MetricPoints.Sum(p => p.GetHistogramCount()).Should().BeGreaterThanOrEqualTo(1);
    }

    private static bool HasAttribute(IReadOnlyList<KeyValuePair<string, object?>>? attributes, string key, string expectedValue)
    {
        if (attributes is null)
        {
            return false;
        }

        foreach (var attribute in attributes)
        {
            if (attribute.Key == key && string.Equals(attribute.Value?.ToString(), expectedValue, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasTag(ReadOnlyTagCollection tags, string key, string expectedValue)
    {
        foreach (var tag in tags)
        {
            if (tag.Key == key && string.Equals(tag.Value?.ToString(), expectedValue, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string CreateDpopProof(ECDsaSecurityKey securityKey, Dictionary<string, string> jwkObject,
        string jti, string url, string? nonce)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = jti,
            ["htm"] = "GET",
            ["htu"] = url,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims["nonce"] = nonce;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = jwkObject
            }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string ComputeEcThumbprint(Dictionary<string, string> jwk)
    {
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk["crv"],
            ["kty"] = jwk["kty"],
            ["x"] = jwk["x"],
            ["y"] = jwk["y"]
        }, TestJsonContext.Default.DictionaryStringString);

        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}