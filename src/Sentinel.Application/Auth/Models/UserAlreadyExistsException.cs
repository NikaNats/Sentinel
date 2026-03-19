namespace Sentinel.Application.Auth.Models;

public sealed class UserAlreadyExistsException(string? message = null) : Exception(message ?? "User already exists.")
{
}
