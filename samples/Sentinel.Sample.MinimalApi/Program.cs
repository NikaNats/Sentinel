/*
 * CONSUMER APPLICATION USAGE GUIDE
 *
 * How to integrate Sentinel Framework Minimal APIs with complete routing control.
 * The host application decides the prefix, not the framework.
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using StackExchange.Redis;
using Sentinel.AspNetCore.Endpoints; // New namespace for Minimal APIs
using Sentinel.Application.DependencyInjection;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Keycloak.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────────────
// 1. AUTHENTICATION & AUTHORIZATION SETUP
// ─────────────────────────────────────────────────────────────────────────────

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://keycloak.example.com/realms/MyRealm";
        options.Audience = "my-application";
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(5);
    });

builder.Services.AddAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// 2. SENTINEL FRAMEWORK SERVICES (Zero MVC Dependencies)
// ─────────────────────────────────────────────────────────────────────────────

// Core authentication & authorization services
builder.Services
    .AddApplication()
    .AddKeycloak(builder.Configuration)
    .AddInfrastructure(builder.Configuration);

// Redis for idempotency caching, session blacklist, DPoP nonce store
var redisConnection = ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis") ?? "localhost:6379");
builder.Services.AddSingleton<IConnectionMultiplexer>(redisConnection);

// ─────────────────────────────────────────────────────────────────────────────
// 3. BUILD APPLICATION
// ─────────────────────────────────────────────────────────────────────────────

var app = builder.Build();

// Middleware pipeline
app.UseHsts();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// 4. MAP SENTINEL ENDPOINTS - HOST CONTROLS THE PREFIX ✨
// ─────────────────────────────────────────────────────────────────────────────

// OPTION A: Standard prefix (recommended for most applications)
app.MapSentinelSecurity("api/v1/identity");
// Routes: POST /api/v1/identity/auth/refresh, /auth/change-password, /auth/logout, etc.

// OPTION B: Minimal prefix (for minimalist APIs)
// app.MapSentinelSecurity("api/security");
// Routes: POST /api/security/auth/refresh, etc.

// OPTION C: Root-level endpoints (not recommended, but possible)
// app.MapSentinelSecurity("");
// Routes: POST /auth/refresh, /ssf/events, etc.

// HOST APPLICATION'S OWN ENDPOINTS (Not affected by Sentinel routing)
app.MapControllers(); // Your business logic controllers
app.MapHealthChecks("/health");

// Show endpoint summary for debugging
app.Run();
