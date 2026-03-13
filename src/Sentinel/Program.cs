using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Application.Auth.Models;
using Sentinel.Infrastructure.Auth;
using Sentinel.Infrastructure.Cache;
using Sentinel.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddControllers();

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

builder.Services.AddSingleton<IJtiReplayCache, JtiReplayCache>();
builder.Services.AddSingleton<IDpopProofValidator, DpopProofValidator>();
builder.Services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Keycloak:Authority"];
        options.Audience = builder.Configuration["Keycloak:Audience"];
        options.RequireHttpsMetadata = true;
        options.RefreshOnIssuerKeyNotFound = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidAlgorithms = ["PS256", "ES256"],
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            NameClaimType = "sub",
            RoleClaimType = "realm_access.roles"
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                try
                {
                    var jti = context.Principal?.FindFirst("jti")?.Value;
                    var exp = context.Principal?.FindFirst("exp")?.Value;
                    var cache = context.HttpContext.RequestServices.GetRequiredService<IJtiReplayCache>();

                    if (string.IsNullOrWhiteSpace(jti) || string.IsNullOrWhiteSpace(exp))
                    {
                        context.Fail("Missing required token claims (jti or exp).");
                        return;
                    }

                    var isReplayed = await cache.ExistsAsync(jti, context.HttpContext.RequestAborted);
                    if (isReplayed)
                    {
                        context.Fail("Token replay detected.");
                        return;
                    }

                    if (!long.TryParse(exp, out var expUnix))
                    {
                        context.Fail("Invalid exp claim.");
                        return;
                    }

                    var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
                    var remainingTtl = expTime - DateTimeOffset.UtcNow;
                    if (remainingTtl > TimeSpan.Zero)
                    {
                        await cache.StoreAsync(jti, remainingTtl, context.HttpContext.RequestAborted);
                    }
                }
                catch (ReplayCacheUnavailableException)
                {
                    context.HttpContext.Items["ReplayCacheUnavailable"] = true;
                    context.Fail("Replay cache unavailable.");
                }
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireClaim("acr")
        .Build();

    options.AddPolicy("ReadProfile", policy =>
        policy.RequireAuthenticatedUser()
            .AddRequirements(
                new ScopeRequirement("profile"),
                new AcrRequirement("acr2")));
});

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<DpopValidationMiddleware>();
app.UseMiddleware<ReplayCacheFailureMiddleware>();

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseMiddleware<AcrValidationMiddleware>();
app.UseAuthorization();

app.MapControllers();

app.Run();
