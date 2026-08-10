using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

namespace Sentinel.Contracts.Shared;

/// <summary>
///     Runs a document through a pinned JSON Schema and returns all violations.
///     Contract schemas live under Keycloak/Schemas (embedded), so a schema
///     drift is caught at build/test time, not in production.
/// </summary>
public static class SchemaValidator
{
    /// <summary>
    ///     Schemas carry $id values; Json.Schema registers each $id in its
    ///     global registry exactly once, so built schemas are cached per text
    ///     (building per call fails on the second registration of the same $id).
    /// </summary>
    private static readonly ConcurrentDictionary<string, JsonSchema> Cache = new();

    public sealed record ValidationResult(bool IsValid, IReadOnlyList<string> Errors);

    public static ValidationResult Validate(string schemaJson, string instanceJson)
    {
        var schema = Cache.GetOrAdd(schemaJson, static json => JsonSchema.FromText(json));
        var instance = JsonNode.Parse(instanceJson)
            ?? throw new InvalidOperationException("Instance JSON could not be parsed.");

        var results = new EvaluationOptions
        {
            // Deterministic, ordered output keeps CI failure messages stable.
            OutputFormat = OutputFormat.Hierarchical
        };

        var result = schema.Evaluate(JsonSerializer.SerializeToElement(instance), results);

        var errors = new List<string>();
        CollectErrors(result.Details, errors);

        return new ValidationResult(result.IsValid, errors);
    }

    private static void CollectErrors(IEnumerable<EvaluationResults>? details, List<string> sink)
    {
        if (details is null)
        {
            return;
        }

        foreach (var detail in details)
        {
            if (!detail.IsValid && detail.Errors is { Count: > 0 })
            {
                foreach (var error in detail.Errors.Values)
                {
                    sink.Add(error);
                }
            }

            if (detail.Details is not null)
            {
                CollectErrors(detail.Details, sink);
            }
        }
    }
}