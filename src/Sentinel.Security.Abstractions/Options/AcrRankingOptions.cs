using System.ComponentModel.DataAnnotations;

namespace Sentinel.Security.Abstractions.Options;

/// <summary>
///     Configuration for Authentication Context Class Reference (ACR) ranking.
///     Defines the hierarchical mapping of ACR values to integer ranks for authorization decisions.
/// </summary>
public sealed class AcrRankingOptions
{
    /// <summary>
    ///     Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "AcrRanking";

    /// <summary>
    ///     Gets or sets the dictionary mapping ACR claim values to their integer ranks.
    ///     Lower values indicate weaker authentication, higher values indicate stronger authentication.
    ///     Example: { "acr1": 1, "acr2": 2, "acr3": 3 } or { "aal1": 1, "aal3": 3 }
    /// </summary>
    [Required(ErrorMessage = "AcrRanking rankings are required")]
    public Dictionary<string, int> Rankings { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["acr1"] = 1,
        ["acr2"] = 2,
        ["acr3"] = 3
    };

    /// <summary>
    ///     Validates that the rankings collection is properly configured.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when rankings are empty or null.</exception>
    public void Validate()
    {
        if (Rankings == null || Rankings.Count == 0)
        {
            throw new InvalidOperationException(
                "AcrRankingOptions.Rankings cannot be empty. " +
                "Provide at least one ACR value mapped to a rank.");
        }

        var duplicateRanks = Rankings.Values
            .GroupBy(r => r)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateRanks.Count > 0)
        {
            throw new InvalidOperationException(
                $"AcrRankingOptions.Rankings contains duplicate ranks: {string.Join(", ", duplicateRanks)}. " +
                "Each rank value must be unique.");
        }
    }
}
