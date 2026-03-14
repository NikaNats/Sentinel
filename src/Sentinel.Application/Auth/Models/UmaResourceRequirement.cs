using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Application.Auth.Models;

public sealed record UmaResourceRequirement(string RequiredScope) : IAuthorizationRequirement;
