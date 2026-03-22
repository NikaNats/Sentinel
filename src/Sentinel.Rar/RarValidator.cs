namespace Sentinel.RAR;

/// <summary>
/// Validates request payloads against Rich Authorization Request (RAR) constraints.
/// </summary>
public sealed class RarValidator : IRarValidator
{
    private readonly IAuthorizationDetailMatcher _matcher;
    private readonly RarValidationOptions _options;
    private readonly ILogger<RarValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the RarValidator.
    /// </summary>
    /// <param name="matcher">Provides authorization detail matching logic.</param>
    /// <param name="options">Configuration for RAR validation.</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    public RarValidator(
        IAuthorizationDetailMatcher matcher,
        RarValidationOptions? options = null,
        ILogger<RarValidator>? logger = null)
    {
        _matcher = matcher ?? throw new ArgumentNullException(nameof(matcher));
        _options = options ?? new RarValidationOptions();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RarValidator>.Instance;
    }

    /// <summary>
    /// Validates a request payload against an authorization detail.
    /// </summary>
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

        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var payload = doc.RootElement;

            if (!_matcher.Matches(detail, payload))
            {
                _logger.LogWarning(
                    "Payload does not match authorization detail constraints (type: {Type})",
                    detail.Type);
                return RarValidationResult.Failure(
                    "Request payload does not satisfy authorization constraints.");
            }

            return RarValidationResult.Success(detail);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse request payload as JSON");
            return RarValidationResult.Failure("Request payload is not valid JSON.");
        }
#pragma warning disable CA1031  // Continue validation upon parse failure
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during RAR validation");
            return RarValidationResult.Failure("RAR validation failed due to an internal error.");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Validates a payload by finding and matching a specific authorization detail type.
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
