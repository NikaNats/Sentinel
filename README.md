# Sentinel

A high-security ASP.NET Core Web API implementing FAPI 2.0-compliant authentication with Keycloak 26+, DPoP (Demonstrating Proof-of-Possession), PKCE S256, WebAuthn AAL3, and Redis-backed token replay detection.

## Project Status

**Specification**: [SPEC-0001 - User Authentication & Token Issuance (PAR + PKCE + DPoP)](./src/Sentinel/.specify/specs/SPEC-0001-auth-token-issuance.md)  
**Implementation Plan**: [PLAN-0001 - Auth Implementation](./src/Sentinel/.specify/plans/PLAN-0001-auth-implementation.md)  
**Tasks**: [TASK-0001 - Development Tasks](./src/Sentinel/.specify/tasks/TASK-0001-auth-implementation.md)

## Directory Structure

```
Sentinel/
├── .git/                        ← Git repository
├── .github/                     ← GitHub configuration
├── .gitignore                   ← Git ignore rules
├── .gitattributes              ← Git line ending settings
├── Sentinel.sln                 ← Visual Studio solution
├── README.md                    ← This file
│
├── src/                         ← Source code
│   └── Sentinel/                ← Main Web API project
│       ├── Sentinel.csproj
│       ├── Program.cs
│       ├── Properties/
│       ├── .github/             ← Spec-Kit agents & prompts
│       ├── .specify/            ← Specifications & plans
│       │   ├── specs/           ← Feature specifications
│       │   ├── plans/           ← Implementation plans
│       │   ├── tasks/           ← Development tasks
│       │   ├── templates/       ← Document templates
│       │   ├── scripts/         ← Automation scripts
│       │   └── memory/          ← Spec-Kit memory files
│       ├── Controllers/         ← API endpoints
│       ├── Middleware/          ← Custom middleware
│       ├── Services/            ← Business logic
│       └── Models/              ← Data models
│
└── tests/                       ← Test projects
    └── (Reserved for test assemblies)
```

## Features

### Implemented
- ✅ ASP.NET Core Web API scaffold
- ✅ Spec-Kit integration (Spec-Driven Development)
- ✅ FAPI 2.0 security specification
- ✅ Implementation plan with 28 development tasks
- ✅ Threat model & security analysis

### In Development (Phase 0-8)
- 🔶 Pre-coding gates & security reviews
- 🔶 Keycloak infrastructure setup
- 🔶 Security middleware (DPoP, jti replay, ACR validation)
- 🔶 Integration testing
- 🔶 OpenTelemetry observability

## Technology Stack

| Component | Version | Purpose |
|---|---|---|
| .NET | 11.0 (Preview) | Runtime |
| ASP.NET Core | 11.0 | Web framework |
| Keycloak | 26+ | Authorization server |
| Redis | 7.4+ | Token replay cache |
| OpenTelemetry | 1.9+ | Observability |

## Getting Started

### Prerequisites
- .NET 11.0 SDK or later
- Docker (for Keycloak & Redis in development)
- Git

### Build
```powershell
dotnet build
```

### Run
```powershell
cd src/Sentinel
dotnet run
```

Visit `https://localhost:5001/swagger` for API documentation.

## Development Workflow

This project follows **Spec-Driven Development** using the Spec-Kit framework:

1. **Specification** (`SPEC-0001`) — Detailed security requirements
2. **Planning** (`PLAN-0001`) — Technical implementation strategy
3. **Tasks** (`TASK-0001`) — Actionable development items
4. **Implementation** — Code the features
5. **Testing** — Comprehensive test coverage
6. **Release** — Documentation & deployment

## Security

### Threat Model Mitigations
- ✅ FAPI 2.0 compliance
- ✅ PKCE S256 authorization code protection
- ✅ DPoP sender-constrained tokens
- ✅ WebAuthn AAL3 phishing resistance
- ✅ Redis jti replay cache (fail-closed)
- ✅ Algorithm restriction (PS256/ES256 only)
- ✅ Zero clock skew token validation
- ✅ Rate limiting on auth endpoints

See [SPEC-0001 §5 Threat Model](./src/Sentinel/.specify/specs/SPEC-0001-auth-token-issuance.md#5-threat-model) for details.

## Contributing

This is a spec-driven project using AI-assisted development. All changes must:

1. ✅ Match the linked specification (SPEC-0001)
2. ✅ Follow the implementation plan (PLAN-0001)
3. ✅ Pass security review (threat model checklist)
4. ✅ Include comprehensive tests
5. ✅ Update relevant documentation

## License

Proprietary. See LICENSE file for details.

## Support

For issues, questions, or security concerns:
- 📋 File an issue in GitHub
- 🔒 Security issues: Contact security team
- 📧 Email: [contact information]

---

**Built with Spec-Driven Development** 🌱  
**Powered by GitHub Spec-Kit** 🚀
