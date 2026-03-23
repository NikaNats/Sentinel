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

/// <summary>
/// Discriminated union representing the outcome of a security operation.
/// Prefer this over throwing exceptions for expected failure paths.
/// Use SecurityResultFactory.Create or SecurityResultFactory.Failure to construct instances.
/// </summary>
public readonly record struct SecurityResult<T>
{
    private readonly T? _value;
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
    /// Gets the result value (only valid if <see cref="IsSuccess"/> is true).
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="IsSuccess"/> is false.</exception>
    public T Value => IsSuccess ? _value! : throw new InvalidOperationException($"Cannot get value from failed result: {_errorMessage}");

    private SecurityResult(T value)
    {
        _value = value;
        _errorMessage = null;
    }

    private SecurityResult(string errorMessage)
    {
        _value = default;
        _errorMessage = errorMessage;
    }

    internal static SecurityResult<T> CreateSuccess(T value) => new(value);

    internal static SecurityResult<T> CreateFailure(string errorMessage) => new(errorMessage);
}

/// <summary>
/// Factory methods for creating SecurityResult values.
/// </summary>
public static partial class SecurityResultFactory
{
    /// <summary>
    /// Creates a successful void result.
    /// </summary>
    public static SecurityResult Create() => SecurityResult.CreateSuccess();

    /// <summary>
    /// Creates a failed void result with the given error message.
    /// </summary>
    public static SecurityResult Failure(string errorMessage) => SecurityResult.Failure(errorMessage);

    /// <summary>
    /// Creates a successful result with the given value.
    /// </summary>
    public static SecurityResult<T> Create<T>(T value) => SecurityResult<T>.CreateSuccess(value);

    /// <summary>
    /// Creates a failed result with the given error message.
    /// </summary>
    public static SecurityResult<T> Failure<T>(string errorMessage) => SecurityResult<T>.CreateFailure(errorMessage);
}
