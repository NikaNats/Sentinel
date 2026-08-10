using Microsoft.OpenApi;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.OpenApi;

/// <summary>
///     CONTRACT: security-scheme &amp; endpoint-protection policy.
///
///     Pins the security topology documented in the OpenAPI components:
///     bearer JWT (primary) + DPoP proof (holder-of-key) stay available with
///     their exact shapes, per-endpoint requirements never weaken, and the
///     explicit public allowlist stays public.
/// </summary>
[Collection(OpenApiContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "OpenAPI 3.1 contract document")]
public sealed class SecuritySchemeContractTests(OpenApiContractFixture fixture)
{
    public static readonly string[] PublicAllowlist =
    [
        "/healthz",
        "/api/system/security/auth/refresh",
        "/api/system/security/auth/backchannel-logout",
        "/api/system/security/auth/token-exchange",
        "/api/system/security/ssf/events"
    ];

    private readonly OpenApiContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: pinned security schemes are still defined with the same shape")]
    public void SecuritySchemes_RemainDefined()
    {
        var violations = new List<string>();
        foreach (var (name, baseline) in _fixture.SecuritySchemes)
        {
            if (!_fixture.Document.Components!.SecuritySchemes!.TryGetValue(name, out var current))
            {
                violations.Add($"{name} (scheme removed)");
                continue;
            }
            var currentScheme = current!;

            if (baseline.Type is not null
                && !string.Equals(baseline.Type, currentScheme.Type?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: type {baseline.Type} != {currentScheme.Type}");
            }

            if (baseline.Scheme is not null
                && !string.Equals(baseline.Scheme, currentScheme.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: http scheme {baseline.Scheme} != {currentScheme.Scheme}");
            }

            if (baseline.In is not null
                && !string.Equals(baseline.In, currentScheme.In?.ToString() ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: header location {baseline.In} != {currentScheme.In}");
            }

            if (baseline.Name is not null
                && !string.Equals(baseline.Name, currentScheme.Name, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"{name}: header name {baseline.Name} != {currentScheme.Name}");
            }
        }

        violations.Should().BeEmpty("security schemes must not change shape");
    }

    [Fact(DisplayName = "CONTRACT: the DPoP proof header requirement is never removed")]
    public void DPoP_Scheme_IsDeclared()
    {
        _fixture.Document.Components!.SecuritySchemes.Should().ContainKey("DPoPProof");
        var dpop = _fixture.Document.Components!.SecuritySchemes["DPoPProof"];
        dpop!.Type.Should().Be(SecuritySchemeType.ApiKey);
        dpop.In.Should().Be(ParameterLocation.Header);
        dpop.Name.Should().Be("DPoP");
    }

    [Fact(DisplayName = "CONTRACT: pinned security requirements never weaken")]
    public void ProtectedEndpoints_KeepBaselineRequirements()
    {
        var violations = new List<string>();
        foreach (var baselinePath in _fixture.BaselinePaths)
        {
            if (!_fixture.Document.Paths.TryGetValue(baselinePath.Name, out var pathItem))
            {
                continue;
            }

            foreach (var baselineOperation in baselinePath.Operations)
            {
                var httpMethod = new HttpMethod(baselineOperation.Method.ToUpperInvariant());
                if (!pathItem!.Operations!.TryGetValue(httpMethod, out var current))
                {
                    continue;
                }

                var effective = EffectiveSchemes(current!).ToArray();
                foreach (var pinnedScheme in baselineOperation.Security)
                {
                    if (!effective.Contains(pinnedScheme, StringComparer.OrdinalIgnoreCase))
                    {
                        violations.Add(
                            $"{pinnedScheme} ({baselineOperation.Method.ToUpperInvariant()} {baselinePath.Name})");
                    }
                }
            }
        }

        violations.Should().BeEmpty("weakening the required scheme of an endpoint breaks clients");
    }

    [Fact(DisplayName = "CONTRACT: allowlisted endpoints stay public (no accidental hardening)")]
    public void PublicAllowlist_StaysPublic()
    {
        var violations = new List<string>();
        foreach (var (pathName, pathItem) in _fixture.Document.Paths)
        {
            if (!IsPublicAllowlist(pathName))
            {
                continue;
            }

            foreach (var (httpMethod, operation) in pathItem.Operations ?? new Dictionary<HttpMethod, OpenApiOperation>())
            {
                if (EffectiveSchemes(operation).Count > 0)
                {
                    violations.Add($"{pathName} {httpMethod.Method}");
                }
            }
        }

        violations.Should().BeEmpty("allowlisted public endpoints must remain unauthenticated");
    }

    private static HashSet<string> EffectiveSchemes(OpenApiOperation operation)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var requirement in operation.Security ?? new List<OpenApiSecurityRequirement>())
        {
            foreach (var schemeReference in requirement.Keys)
            {
                if (schemeReference!.Reference?.Id is { Length: > 0 } id)
                {
                    names.Add(id);
                }
            }
        }

        return names;
    }

    private static bool IsPublicAllowlist(string pathName)
        => pathName == "/" || PublicAllowlist.Contains(pathName);
}