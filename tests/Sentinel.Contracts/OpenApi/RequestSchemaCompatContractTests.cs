using Microsoft.OpenApi;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.OpenApi;

/// <summary>
///     CONTRACT: request-schema compatibility.
///
///     A documented required request field that disappears is a breaking
///     change: clients can no longer construct valid calls. The baseline
///     records the required properties of every request schema; the current
///     document must still declare them (directly or through the same $ref
///     target).
/// </summary>
[Collection(OpenApiContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "OpenAPI 3.1 contract document")]
public sealed class RequestSchemaCompatContractTests(OpenApiContractFixture fixture)
{
    private readonly OpenApiContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: pinned required request fields remain declared")]
    public void PinnedRequiredFields_RemainDeclared()
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
                if (operation.RequiredFields.Length == 0)
                {
                    continue;
                }

                var httpMethod = new HttpMethod(operation.Method.ToUpperInvariant());
                if (!pathItem!.Operations!.TryGetValue(httpMethod, out var current))
                {
                    continue;
                }

                var currentSchema = Dereference(GetJsonSchema(current!));
                foreach (var pinnedField in operation.RequiredFields)
                {
                    if (currentSchema is null || !currentSchema.Required!.Contains(pinnedField))
                    {
                        violations.Add(
                            $"{pinnedField} ({operation.Method.ToUpperInvariant()} {baselinePath.Name})");
                    }
                }
            }
        }

        violations.Should().BeEmpty("dropping a required request field is a CONTRACT-001 violation");
    }

    [Fact(DisplayName = "CONTRACT: documented request bodies still resolve to a concrete schema")]
    public void RequestBodies_ResolveToSchema()
    {
        var unresolvable = new List<string>();
        foreach (var (pathName, pathItem) in _fixture.Document.Paths)
        {
            foreach (var (httpMethod, operation) in pathItem!.Operations!)
            {
                var schema = GetJsonSchema(operation!);
                if (schema is null)
                {
                    continue;
                }

                if (Dereference(schema) is null)
                {
                    unresolvable.Add($"{pathName} {httpMethod.Method}");
                }
            }
        }

        unresolvable.Should().BeEmpty("a documented request body must resolve to a schema");
    }

    private static IOpenApiSchema? GetJsonSchema(OpenApiOperation operation)
    {
        if (operation.RequestBody?.Content is not { } content)
        {
            return null;
        }

        foreach (var (mediaType, media) in content)
        {
            if (mediaType.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                return media.Schema;
            }
        }

        foreach (var (_, media) in content)
        {
            return media.Schema;
        }

        return null;
    }

    private static OpenApiSchema? Dereference(IOpenApiSchema? schema)
    {
        var seen = new HashSet<OpenApiSchemaReference>();
        while (schema is OpenApiSchemaReference schemaRef)
        {
            if (schemaRef.UnresolvedReference || !seen.Add(schemaRef))
            {
                return null;
            }

            schema = schemaRef.Target;
        }

        return schema as OpenApiSchema;
    }
}