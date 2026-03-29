using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.DependencyInjection;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Infrastructure.DependencyInjection;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Security;
using Sentinel.Security.Abstractions.SSF;
using Sentinel.SSF;
using Sentinel.Tests.Shared.Fixtures;
using ApplicationAuthRevocationService = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;
using ApplicationSsfEventProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;
using SecuritySsfEventProcessor = Sentinel.Security.Abstractions.SSF.ISsfEventProcessor;

namespace Sentinel.Tests.Shared;

#pragma warning disable CA1052
#pragma warning disable CA1859

public partial class Program
{
	public static void Main(string[] args)
	{
		var builder = WebApplication.CreateBuilder(args);

		builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
		{
			["ConnectionStrings:Postgres"] = "Host=localhost;Port=5432;Database=sentinel_test;Username=sentinel;Password=sentinel_password",
			["Sentinel:Redis:EndPoint"] = "localhost:6379,abortConnect=false",
			["Sentinel:Redis:EnableInMemoryFallback"] = "true",
			["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
			["Keycloak:Audience"] = "sentinel-api",
			["Keycloak:RequireHttpsMetadata"] = "false",
			["Keycloak:Admin:ClientId"] = "sentinel-api",
			["Keycloak:Admin:ClientSecret"] = "sentinel-test-secret",
			["Ssf:Enabled"] = "true",
			["Ssf:RequireAuthToken"] = "false",
			["Sentinel:Ssf:SessionRevocationTtlSeconds"] = "28800",
			["Sentinel:Ssf:MaxEventAgeSeconds"] = "300",
			["Sentinel:Ssf:AllowedClockSkewSeconds"] = "300",
			["DPoP:RequireNonce"] = "false"
		});

		builder.Configuration.AddInMemoryCollection(TestCryptographyHelper.GenerateTestCryptographyConfig());

		builder.Services
			.AddApplicationLayer(builder.Configuration)
			.AddInfrastructureLayer(builder.Configuration)
			.AddSsfProcessing(builder.Configuration);

		builder.Services.AddSentinelAspNetCore()
			.AddAll()
			.ConfigureAcrRanking();

		builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
			.AddJwtBearer(options =>
			{
				options.MapInboundClaims = false;
				options.Events = new JwtBearerEvents
				{
					OnMessageReceived = context =>
					{
						var authHeader = context.Request.Headers.Authorization.ToString();
						if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
						{
							context.Token = authHeader["DPoP ".Length..].Trim();
						}

						return Task.CompletedTask;
					}
				};
				options.RequireHttpsMetadata = false;
				options.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey,
					ValidateIssuer = true,
					ValidIssuer = "https://localhost:8443/realms/sentinel",
					ValidateAudience = true,
					ValidAudience = "sentinel-api",
					ValidateLifetime = true,
					ClockSkew = TimeSpan.FromSeconds(5)
				};
			});

		builder.Services.AddAuthorizationBuilder()
			.AddPolicy("ScopeProfile", policy =>
				policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("profile")))
			.AddPolicy("ScopeDocumentsRead", policy =>
				policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("documents:read")))
			.AddPolicy("ScopeDocumentsWrite", policy =>
				policy.RequireAuthenticatedUser().AddRequirements(new ScopeRequirement("documents:write")));

		builder.Services.AddRateLimiter(options =>
		{
			options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
			options.AddPolicy("profile", _ =>
				RateLimitPartition.GetConcurrencyLimiter(
					"profile-global",
					_ => new ConcurrencyLimiterOptions
					{
						PermitLimit = 1,
						QueueLimit = 2,
						QueueProcessingOrder = QueueProcessingOrder.OldestFirst
					}));
		});

		builder.Services.AddSingleton<ISsfTokenValidator, TestSsfTokenValidator>();
		builder.Services.AddScoped<ApplicationSsfEventProcessor, SsfEventProcessorAdapter>();
		builder.Services.AddScoped<IAuthRevocationService, AuthRevocationServiceAdapter>();
		builder.Services.AddSingleton(new SdJwtVerificationOptions
		{
			RequireKeyBindingNonce = false,
			KeyBindingMaxAgeSeconds = 300,
			AllowedClockSkewSeconds = 60,
			AllowedDisclosureHashAlgorithms = ["sha-256"]
		});
		builder.Services.AddTransient<ISdJwtTokenValidator, TestSdJwtTokenValidator>();
		builder.Services.AddTransient<SdJwtPresenter>();

		builder.Services.AddSingleton<DocumentStore>();

		var app = builder.Build();

		app.UseRateLimiter();
		app.UseSentinelSecurityPipeline();
		app.UseAuthentication();
		app.UseAuthorization();

		app.MapSentinelSecurity("v1");

		app.MapGet("/v1/profile", GetProfileAsync)
			.RequireRateLimiting("profile");

		var testGroup = app.MapGroup("/v1/test");
		testGroup.MapGet("/protected", GetProtected)
			.RequireAuthorization();
		testGroup.MapGet("/step-up", GetStepUp)
			.RequireAuthorization(Policies.RequireAcr3);

		var documentsGroup = app.MapGroup("/v1/documents")
			.RequireAuthorization();

		documentsGroup.MapGet("/", ListDocuments)
			.RequireAuthorization("ScopeDocumentsRead");

		documentsGroup.MapGet("/{id:guid}", GetDocument)
			.RequireAuthorization("ScopeDocumentsRead");

		documentsGroup.MapPost("/", CreateDocument)
			.RequireAuthorization("ScopeDocumentsWrite")
			.RequireIdempotency();

		documentsGroup.MapDelete("/{id:guid}", DeleteDocument)
			.RequireAuthorization("ScopeDocumentsWrite")
			.RequireIdempotency();

		app.Run();
	}

	private static async Task<IResult> GetProfileAsync(HttpContext context, SdJwtPresenter presenter,
		CancellationToken cancellationToken)
	{
		var authHeader = context.Request.Headers.Authorization.ToString();
		if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
		{
			var bearerToken = authHeader["Bearer ".Length..].Trim();
			if (bearerToken.Contains('~', StringComparison.Ordinal))
			{
				var verification = await presenter.VerifyPresentationAsync(
					bearerToken,
					"sentinel-api",
					expectedNonce: null,
					cancellationToken);

				if (!verification.IsValid || verification.Principal is null)
				{
					return TypedResults.Unauthorized();
				}

				var claims = verification.Principal.Claims
					.GroupBy(c => c.Type, StringComparer.Ordinal)
					.ToDictionary(
						group => group.Key,
						group => group.Last().Value,
						StringComparer.Ordinal);

				return TypedResults.Ok(claims);
			}
		}

		if (context.User.Identity?.IsAuthenticated != true)
		{
			return TypedResults.Unauthorized();
		}

		if (!HasScope(context.User, "profile"))
		{
			return TypedResults.Forbid();
		}

		return TypedResults.Ok(new
		{
			sub = context.User.FindFirst("sub")?.Value,
			acr = context.User.FindFirst("acr")?.Value
		});
	}

	private static IResult GetProtected(ClaimsPrincipal user)
	{
		return TypedResults.Ok(new
		{
			subject = user.FindFirst("sub")?.Value,
			assuranceLevel = user.FindFirst("acr")?.Value
		});
	}

	private static IResult GetStepUp(ClaimsPrincipal user)
	{
		return TypedResults.Ok(new
		{
			subject = user.FindFirst("sub")?.Value,
			assuranceLevel = "acr3"
		});
	}

	private static IResult ListDocuments(HttpContext context, DocumentStore store)
	{
		var subject = context.User.FindFirst("sub")?.Value;
		if (string.IsNullOrWhiteSpace(subject))
		{
			return TypedResults.Unauthorized();
		}

		var documents = store.List(subject)
			.Select(d => new { id = d.Id, title = d.Title })
			.ToArray();

		return TypedResults.Ok(documents);
	}

	private static IResult GetDocument(Guid id, HttpContext context, DocumentStore store)
	{
		var subject = context.User.FindFirst("sub")?.Value;
		if (string.IsNullOrWhiteSpace(subject))
		{
			return TypedResults.Unauthorized();
		}

		if (!store.TryGetForOwner(id, subject, out var document))
		{
			return TypedResults.NotFound();
		}

		return TypedResults.Ok(new
		{
			id = document.Id,
			title = document.Title
		});
	}

	private static IResult CreateDocument(CreateDocumentRequest request, HttpContext context, DocumentStore store)
	{
		var subject = context.User.FindFirst("sub")?.Value;
		if (string.IsNullOrWhiteSpace(subject))
		{
			return TypedResults.Unauthorized();
		}

		if (string.IsNullOrWhiteSpace(request.Title) || string.IsNullOrWhiteSpace(request.Content))
		{
			return TypedResults.Problem(
				type: "/errors/invalid-request",
				title: "Invalid request payload",
				statusCode: StatusCodes.Status400BadRequest);
		}

		if (string.Equals(request.Title, "secrets", StringComparison.OrdinalIgnoreCase))
		{
			context.Response.Headers.Append(
				"WWW-Authenticate",
				"DPoP error=\"insufficient_user_authentication\", error_description=\"Surgical authorization required\"");

			return TypedResults.Problem(
				type: "/errors/insufficient-user-authentication",
				title: "Surgical authorization required",
				statusCode: StatusCodes.Status401Unauthorized);
		}

		var created = store.Create(subject, request.Title.Trim(), request.Content.Trim());
		return TypedResults.Created($"/v1/documents/{created.Id}", new { id = created.Id, title = created.Title });
	}

	private static IResult DeleteDocument(Guid id, HttpContext context, DocumentStore store)
	{
		var subject = context.User.FindFirst("sub")?.Value;
		if (string.IsNullOrWhiteSpace(subject))
		{
			return TypedResults.Unauthorized();
		}

		if (context.Connection.ClientCertificate is null)
		{
			return TypedResults.Problem(
				type: "/errors/mtls-binding-failed",
				title: "mTLS certificate is required",
				statusCode: StatusCodes.Status403Forbidden);
		}

		return store.DeleteForOwner(id, subject)
			? TypedResults.NoContent()
			: TypedResults.NotFound();
	}

	private static bool HasScope(ClaimsPrincipal user, string scope)
	{
		var scopeClaim = user.FindFirst("scope")?.Value;
		if (string.IsNullOrWhiteSpace(scopeClaim))
		{
			return false;
		}

		return scopeClaim
			.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
			.Contains(scope, StringComparer.Ordinal);
	}
}

#pragma warning restore CA1859
#pragma warning restore CA1052

public sealed record CreateDocumentRequest(string Title, string Content);

internal sealed class DocumentStore
{
	private readonly ConcurrentDictionary<Guid, DocumentRecord> documents = new();

	public IEnumerable<DocumentRecord> List(string ownerSubject)
	{
		return documents.Values.Where(d => string.Equals(d.OwnerSubject, ownerSubject, StringComparison.Ordinal));
	}

	public bool TryGetForOwner(Guid id, string ownerSubject, out DocumentRecord document)
	{
		if (documents.TryGetValue(id, out var existing)
			&& string.Equals(existing.OwnerSubject, ownerSubject, StringComparison.Ordinal))
		{
			document = existing;
			return true;
		}

		document = default!;
		return false;
	}

	public DocumentRecord Create(string ownerSubject, string title, string content)
	{
		var record = new DocumentRecord(Guid.NewGuid(), ownerSubject, title, content, DateTimeOffset.UtcNow);
		documents[record.Id] = record;
		return record;
	}

	public bool DeleteForOwner(Guid id, string ownerSubject)
	{
		if (!documents.TryGetValue(id, out var existing)
			|| !string.Equals(existing.OwnerSubject, ownerSubject, StringComparison.Ordinal))
		{
			return false;
		}

		return documents.TryRemove(id, out _);
	}
}

internal sealed record DocumentRecord(
	Guid Id,
	string OwnerSubject,
	string Title,
	string Content,
	DateTimeOffset CreatedUtc);

internal sealed class TestSdJwtTokenValidator : ISdJwtTokenValidator
{
	private static readonly JsonWebTokenHandler TokenHandler = new();

	public async Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(
		string issuerJwt,
		string expectedAudience,
		CancellationToken cancellationToken = default)
	{
		if (!TokenHandler.CanReadToken(issuerJwt))
		{
			return SdJwtIssuerTokenValidationResult.Failure("Issuer token is not a readable JWT.");
		}

		var validation = await TokenHandler.ValidateTokenAsync(issuerJwt, new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey,
			ValidateIssuer = true,
			ValidIssuer = "https://localhost:8443/realms/sentinel",
			ValidateAudience = true,
			ValidAudience = expectedAudience,
			ValidateLifetime = true,
			ClockSkew = TimeSpan.FromSeconds(5)
		});

		if (!validation.IsValid)
		{
			return SdJwtIssuerTokenValidationResult.Failure("Issuer token validation failed.");
		}

		return SdJwtIssuerTokenValidationResult.Success(TokenHandler.ReadJsonWebToken(issuerJwt));
	}
}

internal sealed class TestSsfTokenValidator : ISsfTokenValidator
{
	private static readonly JsonWebTokenHandler TokenHandler = new();

	public async Task<SsfValidationResult> ValidateAsync(string setToken, CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(setToken) || !TokenHandler.CanReadToken(setToken))
		{
			return SsfValidationResult.Fail("SET token format is invalid.");
		}

		var validation = await TokenHandler.ValidateTokenAsync(setToken, new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey,
			ValidateIssuer = true,
			ValidIssuer = "https://localhost:8443/realms/sentinel",
			ValidateAudience = true,
			ValidAudience = "sentinel-api",
			ValidateLifetime = true,
			ClockSkew = TimeSpan.FromSeconds(5)
		});

		if (!validation.IsValid)
		{
			return SsfValidationResult.Fail("SET signature or claims validation failed.");
		}

		var token = TokenHandler.ReadJsonWebToken(setToken);
		if (!token.TryGetPayloadValue<JsonElement>("events", out var eventsElement)
			|| eventsElement.ValueKind != JsonValueKind.Object)
		{
			return SsfValidationResult.Fail("SET token does not contain valid events payload.");
		}

		var events = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
		foreach (var property in eventsElement.EnumerateObject())
		{
			events[property.Name] = property.Value;
		}

		var issuer = token.Issuer;
		var audience = token.Audiences.FirstOrDefault() ?? "sentinel-api";
		var subject = token.Subject;
		if (!token.TryGetPayloadValue<long>("iat", out var issuedAt))
		{
			issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		}

		if (!token.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
		{
			jti = Guid.NewGuid().ToString("N");
		}

		return SsfValidationResult.Success(new SsfEventToken(issuer, issuedAt, jti, audience, subject, events));
	}
}

internal sealed class AuthRevocationServiceAdapter(ApplicationAuthRevocationService inner)
	: IAuthRevocationService
{
	public async Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
	{
		_ = await inner.RevokeAllSessionsAsync(subject, cancellationToken);
	}
}

internal sealed class SsfEventProcessorAdapter(SecuritySsfEventProcessor inner) : ApplicationSsfEventProcessor
{
	public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
	{
		var result = await inner.ProcessAsync(setToken, ct);
		if (result.IsSuccess)
		{
			return SsfProcessResult.Success();
		}

		throw new InvalidOperationException(result.ErrorMessage ?? "SSF processing failed.");
	}
}
