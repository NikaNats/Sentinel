using System.Text.Json;
using Microsoft.OpenApi;
using Microsoft.OpenApi.Reader;

namespace Sentinel.Contracts.OpenApi;

/// <summary>
///     Contract fixture: parses the REAL docs/OPENAPI_3_1.yaml with the
///     Microsoft.OpenApi parser and loads the CONTRACT-001 v1 baseline snapshot
///     that pins its commit-binding facts.
/// </summary>
public sealed class OpenApiContractFixture
{
    public const string BaselineResourceName =
        "Sentinel.Contracts.OpenApi.Baselines.v1-baseline.json";

    public OpenApiContractFixture()
    {
        var text = File.ReadAllText(FindSpecPath());

        var settings = new OpenApiReaderSettings();
        settings.AddYamlReader();

        var result = OpenApiDocument.Parse(text, "yaml", settings);
        Document = result.Document
            ?? throw new InvalidOperationException(
                "Microsoft.OpenApi failed to produce a document (see ParseDiagnostic).");
        ParseDiagnostic = result.Diagnostic
            ?? throw new InvalidOperationException("Parser returned no diagnostics.");

        var baselineAssembly = typeof(OpenApiContractFixture).Assembly;
        using var stream = baselineAssembly.GetManifestResourceStream(BaselineResourceName)!;
        using var readerStream = new MemoryStream();
        stream.CopyTo(readerStream);
        BaselineJson = readerStream.ToArray();
    }

    public OpenApiDocument Document { get; }

    /// <summary>Parser diagnostics from the Microsoft.OpenApi read pass.</summary>
    public OpenApiDiagnostic ParseDiagnostic { get; }

    /// <summary>The raw v1-baseline.json snapshot (UTF-8 bytes of the embedded resource).</summary>
    public byte[] BaselineJson { get; }

    public JsonDocument BaselineDoc => JsonDocument.Parse(BaselineJson);

    public IEnumerable<BaselinePath> BaselinePaths => BaselineDoc.RootElement
        .GetProperty("paths")
        .EnumerateObject()
        .Select(path => new BaselinePath(
            path.Name,
            path.Value.EnumerateObject().Select(operation => new OperationSnapshot(
                operation.Name,
                operation.Value.GetProperty("responses")
                    .EnumerateArray().Select(r => r.GetString()!).ToArray(),
                operation.Value.GetProperty("security")
                    .EnumerateArray().Select(s => s.GetString()!).ToArray(),
                operation.Value.GetProperty("requestRequired")
                    .EnumerateArray().Select(r => r.GetString()!).ToArray()))
                .ToArray()))
        .ToArray();

    public IReadOnlyDictionary<string, BaselineScheme> SecuritySchemes => BaselineDoc
        .RootElement.GetProperty("securitySchemes").EnumerateObject()
        .ToDictionary(
            scheme => scheme.Name,
            scheme => new BaselineScheme(
                scheme.Value.TryGetProperty("type", out var t) ? t.GetString() : null,
                scheme.Value.TryGetProperty("scheme", out var s) ? s.GetString() : null,
                scheme.Value.TryGetProperty("in", out var i) ? i.GetString() : null,
                scheme.Value.TryGetProperty("name", out var n) ? n.GetString() : null));

    private static string FindSpecPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
            {
                return Path.Combine(directory.FullName, "docs", "OPENAPI_3_1.yaml");
            }

            directory = directory.Parent;
        }

        return Path.Combine(Directory.GetCurrentDirectory(), "docs", "OPENAPI_3_1.yaml");
    }
}

public sealed record OperationSnapshot(
    string Method,
    string[] Responses,
    string[] Security,
    string[] RequiredFields);

public sealed record BaselinePath(string Name, OperationSnapshot[] Operations);

public sealed record BaselineScheme(string? Type, string? Scheme, string? In, string? Name);

[CollectionDefinition(Name)]
public sealed class OpenApiContractCollection : ICollectionFixture<OpenApiContractFixture>
{
    public const string Name = "OpenAPI Contract";
}