namespace Sentinel.Security.Abstractions.Results;

/// <summary>
/// Result type for operations that don't return a value, only success/failure status.
/// </summary>
public readonly record struct SecurityResult
{
    private readonly string? _errorMessage;

    /// <summary>
    /// Gets a value indicating whether the operation was successful.
    /// </summary>
    public bool IsSuccess => _errorMessage is null;

    /// <summary>
    /// Gets the error message if the operation failed.
    /// </summary>
    public string? ErrorMessage => _errorMessage;

    /// <summary>
    /// A shared pre-constructed successful result.
    /// </summary>
#pragma warning disable CA1805 // Exception for intentional default initialization
    public static readonly SecurityResult SuccessValue;
#pragma warning restore CA1805

    internal SecurityResult(string? errorMessage)
    {
        _errorMessage = errorMessage;
    }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static SecurityResult CreateSuccess() => SuccessValue;

    /// <summary>
    /// Creates a failed result with the given error message.
    /// </summary>
    public static SecurityResult Failure(string errorMessage) => new(errorMessage);
}
