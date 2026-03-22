namespace Sentinel.RAR;

/// <summary>
/// Extracts and parses Rich Authorization Request (RAR) authorization details from a claims principal.
/// </summary>
public interface IRarExtractor
{
    /// <summary>
    /// Extracts authorization details from a claims principal's authorization_details claim.
    /// </summary>
    /// <remarks>
    /// The authorization_details claim should contain a JSON array of authorization detail objects.
    /// If the claim is missing, malformed, or empty, defaults to an empty array.
    /// </remarks>
    /// <param name="claimsJson">The JSON string from the authorization_details claim.</param>
    /// <returns>Extraction result containing parsed details or error information.</returns>
    RarExtractionResult Extract(string claimsJson);
}

/// <summary>
/// Validates payloads against Rich Authorization Request (RAR) authorization details.
/// </summary>
public interface IRarValidator
{
    /// <summary>
    /// Validates a request payload against the given authorization detail.
    /// </summary>
    /// <remarks>
    /// The validation checks that the request payload satisfies the constraints
    /// specified in the authorization detail. For example:
    /// - Authorization detail specifies amount=100, currency=USD, transactionId=abc123
    /// - Request payload must have matching amount, currency, and transaction ID
    /// 
    /// The specific validation rules depend on the authorization detail type and
    /// the payload structure.
    /// </remarks>
    /// <param name="detail">The authorization detail to validate against.</param>
    /// <param name="payloadJson">The request payload as a JSON string.</param>
    /// <returns>Validation result indicating success or describing the failure.</returns>
    RarValidationResult Validate(AuthorizationDetail detail, string payloadJson);

    /// <summary>
    /// Validates a request payload against a set of authorization details.
    /// </summary>
    /// <remarks>
    /// Searches for an authorization detail that matches the payload.
    /// Returns success on the first match or failure if no match is found.
    /// </remarks>
    /// <param name="details">The authorization details to validate against.</param>
    /// <param name="detailType">The authorization detail type to find and validate.</param>
    /// <param name="payloadJson">The request payload as a JSON string.</param>
    /// <returns>Validation result indicating success (with matched detail) or failure.</returns>
    RarValidationResult ValidateByType(
        AuthorizationDetail[] details,
        string detailType,
        string payloadJson);
}

/// <summary>
/// Matches authorization detail constraints against request payload properties.
/// Provides extensibility for custom authorization detail types.
/// </summary>
public interface IAuthorizationDetailMatcher
{
    /// <summary>
    /// Matches the authorization detail constraints against the request payload.
    /// </summary>
    /// <remarks>
    /// Implementations should check that all non-null constraints in the authorization detail
    /// are satisfied by the corresponding values in the payload.
    /// </remarks>
    /// <param name="detail">The authorization detail with constraints.</param>
    /// <param name="payload">The request payload as a JsonElement.</param>
    /// <returns>True if the payload satisfies all constraints, false otherwise.</returns>
    bool Matches(AuthorizationDetail detail, JsonElement payload);

    /// <summary>
    /// Gets the supportability weight for a given authorization detail type.
    /// Higher weights are preferred; lower weights indicate less preferred implementations.
    /// </summary>
    /// <remarks>
    /// Used to allow multiple matchers to compete based on specificity.
    /// For example:
    /// - Generic matcher: weight = 0
    /// - Financial transfer matcher: weight = 10 (more specific)
    /// - Custom order matcher: weight = 20 (most specific)
    /// </remarks>
    /// <param name="detailType">The authorization detail type to match.</param>
    /// <returns>Weight indicating preference; 0 if not supported.</returns>
    int GetSupportWeight(string detailType);
}
