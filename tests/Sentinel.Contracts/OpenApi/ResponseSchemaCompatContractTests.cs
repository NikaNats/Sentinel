using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.OpenApi;

/// <summary>
///     CONTRACT: pinned response codes must keep being documented.
///
///     Dropping an error code from the spec breaks clients that handle it, so
///     the baseline response codes must remain a subset of the current
///     document's. Error codes also must always carry an application/json
///     ProblemDetails body.
/// </summary>
[Collection(OpenApiContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "OpenAPI 3.1 contract (docs)")]
public sealed class ResponseSchemaCompatContractTests(OpenApiContractFixture fixture)
{
    private readonly OpenApiContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: pinned response codes are never dropped")]
    public void PinnedResponses_RemainDeclared()
    {
        var violations = new List<string>();
        foreach (var baselinePath in _fixture.BaselinePaths)
        {
            if (!_fixture.Document.Paths.TryGetValue(baselinePath.Name, out var pathItem))
            {
                continue;
            }

            foreach (var operation in baselinePath.Operations)
            {
                var httpMethod = new HttpMethod(operation.Method.ToUpperInvariant());
                if (!pathItem!.Operations!.TryGetValue(httpMethod, out var current))
                {
                    continue;
                }

                var declared = new HashSet<string>(current!.Responses!.Keys);
                foreach (var pinned in operation.Responses)
                {
                    if (!declared.Contains(pinned))
                    {
                        violations.Add($"{pinned} ({operation.Method.ToUpperInvariant()} {baselinePath.Name})");
                    }
                }
            }
        }

        violations.Should().BeEmpty("dropping a documented response code breaks clients");
    }

    [Fact(DisplayName = "CONTRACT: every error response documents a ProblemDetails body")]
    public void ErrorResponses_DeclareJsonProblemDetails()
    {
        var violations = new List<string>();
        foreach (var (pathName, pathItem) in _fixture.Document.Paths)
        {
            if (pathItem.Operations is not { } operations)
            {
                continue;
            }

            foreach (var (httpMethod, operation) in operations)
            {
                if (operation.Responses is not { } responses)
                {
                    continue;
                }

                foreach (var (code, response) in responses)
                {
                    if (!int.TryParse(code, out var status) || status is < 400 or > 599)
                    {
                        continue;
                    }

                    var hasJson = response.Content is { } content
                        && content.Keys.Any(key =>
                            key.Contains("json", StringComparison.OrdinalIgnoreCase));
                    if (!hasJson)
                    {
                        violations.Add($"{code} ({pathName} {httpMethod.Method})");
                    }
                }
            }
        }

        foreach (var (name, response) in _fixture.Document.Components!.Responses!)
        {
            if (!name.StartsWith("Problem", StringComparison.Ordinal))
            {
                continue;
            }

            var hasJson = response!.Content!.Keys.Any(key =>
                key.Contains("json", StringComparison.OrdinalIgnoreCase));
            if (!hasJson)
            {
                violations.Add($"components.responses.{name}");
            }
        }

        violations.Should().BeEmpty("error responses must declare an application/json body");
    }
}