using System.Net;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.OpenApi;

/// <summary>
///     CONTRACT: the v1 baseline's endpoint map stays fully available.
///
///     Removals are breaking. Additions are invisible here (they do not break
///     contracts), but the next baseline regeneration will pick them up.
/// </summary>
[Collection(OpenApiContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "OpenAPI 3.1 contract document")]
public sealed class EndpointAvailabilityContractTests(OpenApiContractFixture fixture)
{
    private readonly OpenApiContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: baseline spec parses without errors (Microsoft.OpenApi)")]
    public void Document_ParsesWithoutErrors()
    {
        _fixture.ParseDiagnostic.Errors.Should().BeEmpty(
            "the contract document must parse cleanly under Microsoft.OpenApi");
    }

    [Fact(DisplayName = "CONTRACT: every baseline path is still served")]
    public void BaselinePaths_RemainAvailable()
    {
        var missing = _fixture.BaselinePaths
            .Where(baseline => !_fixture.Document.Paths.ContainsKey(baseline.Name))
            .Select(baseline => baseline.Name)
            .ToArray();

        missing.Should().BeEmpty("deleting a pinned endpoint is a CONTRACT-001 violation");
    }

    [Fact(DisplayName = "CONTRACT: every baseline HTTP method is still served")]
    public void BaselineOperations_RemainServed()
    {
        var removed = new List<string>();
        foreach (var baselinePath in _fixture.BaselinePaths)
        {
            if (!_fixture.Document.Paths.TryGetValue(baselinePath.Name, out var pathItem))
            {
                continue;
            }

            foreach (var operation in baselinePath.Operations)
            {
                var httpMethod = new HttpMethod(operation.Method.ToUpperInvariant());
                if (!pathItem!.Operations!.ContainsKey(httpMethod))
                {
                    removed.Add($"{operation.Method.ToUpperInvariant()} {baselinePath.Name}");
                }
            }
        }

        removed.Should().BeEmpty("removing a pinned HTTP method is a CONTRACT-001 violation");
    }

    [Fact(DisplayName = "CONTRACT: operations expose the endpoint map root ('/')")]
    public void RootEndpoint_StillDeclared()
    {
        _fixture.Document.Paths.Should().ContainKey("/");
    }
}