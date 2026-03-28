using Microsoft.Extensions.Options;
using Sentinel.Domain.Auth.Rar;

namespace Sentinel.RAR;

/// <summary>
///     High-assurance RAR validator with polymorphic matcher routing.
///     Validates request payloads against Rich Authorization Request (RAR) constraints
///     using a priority-weighted matcher selection strategy.
/// </summary>
public sealed class RarValidator : IRarValidator
{
    private readonly ILogger<RarValidator> _logger;
    private readonly IEnumerable<IAuthorizationDetailMatcher> _matchers;
    private readonly RarValidationOptions _options;

    /// <summary>
    ///     Initializes a new instance of the RarValidator.
    /// </summary>
    /// <param name="matchers">Collection of matchers supporting different authorization detail types.</param>
    /// <param name="options">Configuration for RAR validation (from DI).</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    /// <remarks>
    ///     ✅ FIX: Accept a collection of matchers to support polymorphic evaluation.
    ///     Replaces the anti-pattern of single-matcher injection with proper routing.
    /// </remarks>
    public RarValidator(
        IEnumerable<IAuthorizationDetailMatcher> matchers,
        IOptions<RarValidationOptions> options,
        ILogger<RarValidator> logger)
    {
        _matchers = matchers ?? throw new ArgumentNullException(nameof(matchers));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    ///     Validates a request payload against an authorization detail.
    /// </summary>
    /// <remarks>
    ///     Uses polymorphic routing to select the highest-weight matcher capable of handling
    ///     the authorization detail type. This enables extensibility without modifying RarValidator.
    /// </remarks>
    public RarValidationResult Validate(AuthorizationDetail detail, string payloadJson)
    {
        if (detail is null)
        {
            return RarValidationResult.Failure("Authorization detail is required.");
        }

        if (string.IsNullOrWhiteSpace(payloadJson))
        {
            return RarValidationResult.Failure("Request payload is required.");
        }

        // ✅ FIX: Polymorphic routing based on SupportWeight
        var selectedMatcher = _matchers
            .Select(m => new { Matcher = m, Weight = m.GetSupportWeight(detail.Type) })
            .Where(x => x.Weight > 0)
            .OrderByDescending(x => x.Weight)
            .FirstOrDefault()?.Matcher;

        if (selectedMatcher is null)
        {
            _logger.LogWarning("No capable RAR matcher found for type: {Type}", detail.Type);
            return RarValidationResult.Failure($"Unsupported authorization detail type: {detail.Type}");
        }

        try
        {
            using var doc = JsonDocument.Parse(payloadJson);

            // ✅ FIX: Pass the unified _options down to the matcher to ensure CaseSensitiveComparison is respected
            if (!selectedMatcher.Matches(detail, doc.RootElement, _options))
            {
                _logger.LogWarning("RAR bounds violation. Type: {Type}", detail.Type);
                return RarValidationResult.Failure("Request payload violates signed authorization constraints.");
            }

            return RarValidationResult.Success(detail);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse payload for RAR evaluation.");
            return RarValidationResult.Failure("Request payload is not valid JSON.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Unexpected error during RAR validation");
            return RarValidationResult.Failure("RAR validation failed due to an internal error.");
        }
    }

    /// <summary>
    ///     Validates a payload by finding and matching a specific authorization detail type.
    /// </summary>
    public RarValidationResult ValidateByType(
        AuthorizationDetail[] details,
        string detailType,
        string payloadJson)
    {
        if (details is null || details.Length == 0)
        {
            return RarValidationResult.Failure("Authorization details are required.");
        }

        if (string.IsNullOrWhiteSpace(detailType))
        {
            return RarValidationResult.Failure("Authorization detail type is required.");
        }

        if (string.IsNullOrWhiteSpace(payloadJson))
        {
            return RarValidationResult.Failure("Request payload is required.");
        }

        // Find matching detail by type
        var comparer = _options.CaseSensitiveComparison
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;

        var matchingDetail = details.FirstOrDefault(d =>
            string.Equals(d.Type, detailType, comparer));

        if (matchingDetail is null)
        {
            _logger.LogWarning(
                "No authorization detail found for type: {Type}",
                detailType);
            return RarValidationResult.Failure(
                $"No authorization detail found for type '{detailType}'.");
        }

        return Validate(matchingDetail, payloadJson);
    }
}
