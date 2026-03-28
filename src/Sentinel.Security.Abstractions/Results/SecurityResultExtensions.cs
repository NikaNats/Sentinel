namespace Sentinel.Security.Abstractions.Results;

/// <summary>
///     Railway Oriented Programming (ROP) extension methods for SecurityResult&lt;T&gt;.
///     Enables functional composition of security operations with automatic error propagation.
/// </summary>
public static class SecurityResultExtensions
{
    /// <summary>
    ///     Binds (flatMaps) the result to a new operation, composing security checks.
    ///     If the current result is a failure, short-circuits and returns the failure.
    /// </summary>
    /// <typeparam name="T">The type of the current result value.</typeparam>
    /// <typeparam name="TNext">The type of the next result value.</typeparam>
    /// <param name="result">The current result to bind.</param>
    /// <param name="binder">A function that takes the value and returns a new SecurityResult.</param>
    /// <returns>The result of the binder if successful; otherwise the original failure.</returns>
    public static SecurityResult<TNext> Bind<T, TNext>(
        this SecurityResult<T> result,
        Func<T, SecurityResult<TNext>> binder) =>
        result.IsSuccess
            ? binder(result.Value)
            : SecurityResultFactory.Failure<TNext>(result.ErrorMessage!);

    /// <summary>
    ///     Binds (flatMaps) the result to an async operation, composing security checks asynchronously.
    ///     If the current result is a failure, short-circuits and returns the failure.
    /// </summary>
    /// <typeparam name="T">The type of the current result value.</typeparam>
    /// <typeparam name="TNext">The type of the next result value.</typeparam>
    /// <param name="result">The current result to bind.</param>
    /// <param name="asyncBinder">An async function that takes the value and returns a new SecurityResult.</param>
    /// <returns>A task representing the result of the binder if successful; otherwise the original failure.</returns>
    public static async Task<SecurityResult<TNext>> BindAsync<T, TNext>(
        this SecurityResult<T> result,
        Func<T, Task<SecurityResult<TNext>>> asyncBinder)
    {
        if (!result.IsSuccess)
        {
            return SecurityResultFactory.Failure<TNext>(result.ErrorMessage!);
        }

        return await asyncBinder(result.Value);
    }

    /// <summary>
    ///     Maps (transforms) the successful result value to a new value, applying a pure function.
    ///     If the result is a failure, returns the failure unchanged.
    /// </summary>
    /// <typeparam name="T">The type of the current result value.</typeparam>
    /// <typeparam name="TNext">The type of the mapped result value.</typeparam>
    /// <param name="result">The result to map.</param>
    /// <param name="mapper">A pure function that transforms the value.</param>
    /// <returns>A successful result with the transformed value, or the original failure.</returns>
    public static SecurityResult<TNext> Map<T, TNext>(
        this SecurityResult<T> result,
        Func<T, TNext> mapper) =>
        result.IsSuccess
            ? SecurityResultFactory.Create(mapper(result.Value))
            : SecurityResultFactory.Failure<TNext>(result.ErrorMessage!);

    /// <summary>
    ///     Maps (transforms) the successful result value asynchronously.
    ///     If the result is a failure, returns the failure unchanged.
    /// </summary>
    /// <typeparam name="T">The type of the current result value.</typeparam>
    /// <typeparam name="TNext">The type of the mapped result value.</typeparam>
    /// <param name="result">The result to map.</param>
    /// <param name="asyncMapper">An async function that transforms the value.</param>
    /// <returns>A task representing a successful result with the transformed value, or the original failure.</returns>
    public static async Task<SecurityResult<TNext>> MapAsync<T, TNext>(
        this SecurityResult<T> result,
        Func<T, Task<TNext>> asyncMapper)
    {
        if (!result.IsSuccess)
        {
            return SecurityResultFactory.Failure<TNext>(result.ErrorMessage!);
        }

        var mapped = await asyncMapper(result.Value);
        return SecurityResultFactory.Create(mapped);
    }

    /// <summary>
    ///     Matches (pattern matches) the result, applying different functions based on success/failure.
    ///     Use this to extract values or perform different actions based on the result state.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <typeparam name="TResult">The type of the match return value.</typeparam>
    /// <param name="result">The result to match.</param>
    /// <param name="onSuccess">Function to execute if the result is successful.</param>
    /// <param name="onFailure">Function to execute if the result is a failure.</param>
    /// <returns>The result of the appropriate function.</returns>
    public static TResult Match<T, TResult>(
        this SecurityResult<T> result,
        Func<T, TResult> onSuccess,
        Func<string, TResult> onFailure) =>
        result.IsSuccess
            ? onSuccess(result.Value)
            : onFailure(result.ErrorMessage!);

    /// <summary>
    ///     Matches (pattern matches) the result asynchronously.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <typeparam name="TResult">The type of the match return value.</typeparam>
    /// <param name="result">The result to match.</param>
    /// <param name="onSuccess">Async function to execute if the result is successful.</param>
    /// <param name="onFailure">Async function to execute if the result is a failure.</param>
    /// <returns>A task representing the result of the appropriate function.</returns>
    public static async Task<TResult> MatchAsync<T, TResult>(
        this SecurityResult<T> result,
        Func<T, Task<TResult>> onSuccess,
        Func<string, Task<TResult>> onFailure) =>
        result.IsSuccess
            ? await onSuccess(result.Value)
            : await onFailure(result.ErrorMessage!);

    /// <summary>
    ///     Recovers from a failure by providing an alternative value or result.
    ///     If the result is already successful, returns it unchanged.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to recover.</param>
    /// <param name="recover">Function that takes the error message and returns a recovery value.</param>
    /// <returns>The original successful result, or a success result with the recovered value.</returns>
    public static SecurityResult<T> Recover<T>(
        this SecurityResult<T> result,
        Func<string, T> recover) =>
        result.IsSuccess
            ? result
            : SecurityResultFactory.Create(recover(result.ErrorMessage!));

    /// <summary>
    ///     Recovers from a failure by providing an alternative result.
    ///     If the result is already successful, returns it unchanged.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to recover.</param>
    /// <param name="recover">Function that takes the error message and returns an alternative SecurityResult.</param>
    /// <returns>The original successful result, or the result from the recover function.</returns>
    public static SecurityResult<T> RecoverWith<T>(
        this SecurityResult<T> result,
        Func<string, SecurityResult<T>> recover) =>
        result.IsSuccess
            ? result
            : recover(result.ErrorMessage!);

    /// <summary>
    ///     Performs a side effect when the result is successful, without modifying the result.
    ///     Useful for logging, tracking, or triggering notifications.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to tap.</param>
    /// <param name="action">An action to perform on the success value.</param>
    /// <returns>The same result unchanged.</returns>
    public static SecurityResult<T> Tap<T>(
        this SecurityResult<T> result,
        Action<T> action)
    {
        if (result.IsSuccess)
        {
            action(result.Value);
        }

        return result;
    }

    /// <summary>
    ///     Performs an async side effect when the result is successful, without modifying the result.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to tap.</param>
    /// <param name="asyncAction">An async action to perform on the success value.</param>
    /// <returns>A task representing the same result unchanged.</returns>
    public static async Task<SecurityResult<T>> TapAsync<T>(
        this SecurityResult<T> result,
        Func<T, Task> asyncAction)
    {
        if (result.IsSuccess)
        {
            await asyncAction(result.Value);
        }

        return result;
    }

    /// <summary>
    ///     Performs a side effect for both success and failure cases.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to tap.</param>
    /// <param name="onSuccess">Action to perform if successful.</param>
    /// <param name="onFailure">Action to perform if failed.</param>
    /// <returns>The same result unchanged.</returns>
    public static SecurityResult<T> TapEither<T>(
        this SecurityResult<T> result,
        Action<T> onSuccess,
        Action<string> onFailure)
    {
        if (result.IsSuccess)
        {
            onSuccess(result.Value);
        }
        else
        {
            onFailure(result.ErrorMessage!);
        }

        return result;
    }

    /// <summary>
    ///     Gets the value if successful, or a default value if failed.
    ///     Safe way to extract the value without throwing exceptions.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to extract from.</param>
    /// <param name="defaultValue">The default value to return on failure.</param>
    /// <returns>The result value if successful; otherwise the default value.</returns>
    public static T GetValueOrDefault<T>(
        this SecurityResult<T> result,
        T defaultValue) =>
        result.IsSuccess ? result.Value : defaultValue;

    /// <summary>
    ///     Gets the value if successful, or computes a default value if failed.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to extract from.</param>
    /// <param name="defaultFactory">A function that produces the default value on failure.</param>
    /// <returns>The result value if successful; otherwise the computed default value.</returns>
    public static T GetValueOrDefault<T>(
        this SecurityResult<T> result,
        Func<string, T> defaultFactory) =>
        result.IsSuccess ? result.Value : defaultFactory(result.ErrorMessage!);

    /// <summary>
    ///     Filters a successful result based on a predicate.
    ///     If the predicate returns false, returns a failure with the specified error message.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to filter.</param>
    /// <param name="predicate">A function that tests the value.</param>
    /// <param name="errorMessage">The error message to return if the predicate fails.</param>
    /// <returns>The original result if successful and the predicate passes; otherwise a failure.</returns>
    public static SecurityResult<T> Filter<T>(
        this SecurityResult<T> result,
        Func<T, bool> predicate,
        string errorMessage) =>
        result.IsSuccess && predicate(result.Value)
            ? result
            : SecurityResultFactory.Failure<T>(errorMessage);

    /// <summary>
    ///     Converts a SecurityResult to a task if it isn't already async.
    /// </summary>
    /// <typeparam name="T">The type of the result value.</typeparam>
    /// <param name="result">The result to convert.</param>
    /// <returns>A completed task containing the result.</returns>
    public static Task<SecurityResult<T>> AsTask<T>(this SecurityResult<T> result) => Task.FromResult(result);
}
