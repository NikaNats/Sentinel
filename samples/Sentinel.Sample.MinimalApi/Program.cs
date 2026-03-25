/*
 * ULTIMATE MINIMAL API SAMPLE APPLICATION
 *
 * This demonstrates how a 2026 enterprise team consumed the Sentinel Framework:
 * - Zero MVC controllers (pure Minimal APIs)
 * - Envelope cryptography for data at rest
 * - DPoP, mTLS, RAR, and ACR Step-Up security pipelines
 * - Native AOT compatible (no reflection - no WithOpenApi calls)
 * - Microsecond startup times
 */

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.Application.DependencyInjection;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.Infrastructure.Cryptography;
using Sentinel.Keycloak.Extensions;
using Sentinel.Sample.MinimalApi.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────────────
// 1. REGISTER SENTINEL INFRASTRUCTURE LAYERS
// ─────────────────────────────────────────────────────────────────────────────

// Deep infrastructure: Redis, Keycloak, Cryptography, Telemetry
builder.Services
    .AddApplicationLayer()
    .AddKeycloakIntegration(builder.Configuration.GetSection("Sentinel:Keycloak"))
    .AddInfrastructureLayer(builder.Configuration);

// ─────────────────────────────────────────────────────────────────────────────
// 2. APPLICATION-SPECIFIC SERVICES
// ─────────────────────────────────────────────────────────────────────────────

builder.Services.AddSingleton<DocumentRepository>();

var app = builder.Build();

// ─────────────────────────────────────────────────────────────────────────────
// HTTP PIPELINE: Security middleware
// ─────────────────────────────────────────────────────────────────────────────

app.UseDeveloperExceptionPage();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// ROUTING: Domain-Driven Endpoint Mapping
// ─────────────────────────────────────────────────────────────────────────────

// A. Framework endpoints (Framework controls these implementations)
//    Host application decides the routing prefix (not the framework)
app.MapSentinelSecurity("api/system/security");

// B. Business domains (Host application controls these)
app.MapDocumentEndpoints("api/v1/documents");
app.MapFinanceEndpoints("api/v1/finance");

app.Run();
