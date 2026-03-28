namespace Sentinel.Security.Abstractions.Exceptions;

/// <summary>
///     Thrown when an identity provider rejects a user creation request because the user already exists.
///     This is a transient identity provider state that should trigger informational messaging (not error).
/// </summary>
public sealed class UserAlreadyExistsException(string? message = null)
    : Exception(message ?? "The user account already exists in the identity provider.")
{
}
