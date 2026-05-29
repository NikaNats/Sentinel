using ArchUnitNET.Domain;
using ArchUnitNET.Fluent;
using ArchUnitNET.Loader;
using ArchUnitNET.xUnit;
using Sentinel.Application.Auth;
using Sentinel.AspNetCore.Middleware;
using Sentinel.Domain.Users;
using Sentinel.Infrastructure;
using static ArchUnitNET.Fluent.ArchRuleDefinition;
using Assembly = System.Reflection.Assembly;

namespace Sentinel.Tests.Security.Architecture;

public class ArchitectureTests
{
    private static readonly Assembly DomainAssembly = typeof(UserRegistration).Assembly;
    private static readonly Assembly ApplicationAssembly = typeof(Policies).Assembly;
    private static readonly Assembly InfrastructureAssembly = typeof(FipsConfiguration).Assembly;
    private static readonly Assembly AspNetCoreAssembly = typeof(DpopValidationMiddleware).Assembly;

    private static readonly ArchUnitNET.Domain.Architecture TargetArchitecture = new ArchLoader()
        .LoadAssemblies(DomainAssembly, ApplicationAssembly, InfrastructureAssembly, AspNetCoreAssembly)
        .Build();

    private static readonly IObjectProvider<IType> DomainLayer =
        Types().That().ResideInAssembly(DomainAssembly)
            .And().DoNotHaveNameContaining("ThisAssembly")
            .As("Domain Layer");

    private static readonly IObjectProvider<IType> ApplicationLayer =
        Types().That().ResideInAssembly(ApplicationAssembly)
            .And().DoNotHaveNameContaining("ThisAssembly")
            .As("Application Layer");

    private static readonly IObjectProvider<IType> InfrastructureLayer =
        Types().That().ResideInAssembly(InfrastructureAssembly)
            .And().DoNotHaveNameContaining("ThisAssembly")
            .As("Infrastructure Layer");

    private static readonly IObjectProvider<IType> AspNetCoreLayer =
        Types().That().ResideInAssembly(AspNetCoreAssembly)
            .And().DoNotHaveNameContaining("ThisAssembly")
            .As("AspNetCore Layer");

    // =========================================================================
    // 🛡️ Architectural Rules (Executable Rules)
    // =========================================================================

    [Fact(DisplayName = "🛡️ Rule 1: Domain layer must be absolutely isolated (Zero Dependency)")]
    public void DomainLayer_ShouldNotDependOn_ApplicationLayer()
    {
        IArchRule domainIsolationRule = Types().That().Are(DomainLayer).Should()
            .NotDependOnAny(ApplicationLayer)
            .AndShould().NotDependOnAny(InfrastructureLayer)
            .AndShould().NotDependOnAny(AspNetCoreLayer)
            .Because("Domain layer must remain purely abstract and decoupled from concrete technical concerns.");

        domainIsolationRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 2: Application layer must not depend on external code layers (DIP)")]
    public void ApplicationLayer_ShouldNotDependOn_InfrastructureOrAspNetCore()
    {
        IArchRule applicationIsolationRule = Types().That().Are(ApplicationLayer).Should()
            .NotDependOnAny(InfrastructureLayer)
            .AndShould().NotDependOnAny(AspNetCoreLayer)
            .Because(
                "Application layer must only contain business orchestration and depend strictly on abstract ports.");

        applicationIsolationRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 3: Cryptographic and security validators must be internal")]
    public void ConcreteValidators_ShouldBe_Internal()
    {
        IArchRule internalVisibilityRule = Classes().That().HaveNameContaining("Validator")
            .And().DoNotResideInNamespace("Sentinel.Security.Abstractions")
            .And().DoNotHaveNameContaining("Benchmark")
            .And().DoNotHaveNameContaining("Test")
            .Should().BeInternal()
            .Because(
                "Concrete validation engines are internal details and must remain protected within their assemblies.");

        internalVisibilityRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName =
        "🛡️ Rule 4: Cryptographic libraries must not be directly accessed by Domain or Application layers")]
    public void DomainAndApplication_ShouldNotUse_RawCryptography()
    {
        IArchRule cryptoGuardRule = Types().That().Are(DomainLayer).Or().Are(ApplicationLayer).Should()
            .NotDependOnAny(Types().That().ResideInNamespace("System.Security.Cryptography"))
            .Because(
                "Domain and Application layers must use abstract services (IEncryptionService) instead of instantiating raw cryptographic algorithms.");

        cryptoGuardRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 5: Request, Response, and DTO types must be sealed to enforce immutability")]
    public void Dtos_ShouldBe_Sealed()
    {
        IArchRule sealedDtoRule = Classes().That().HaveNameEndingWith("Request")
            .Or().HaveNameEndingWith("Response")
            .Or().HaveNameEndingWith("Dto")
            .And().DoNotHaveNameContaining("Test")
            .Should().BeSealed()
            .Because(
                "Data Transfer Objects and requests/responses must be immutable and sealed to prevent state mutation.");

        sealedDtoRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 6: ASP.NET Core Middlewares must be sealed and internal")]
    public void Middlewares_ShouldBe_SealedAndInternal()
    {
        IArchRule middlewareRule = Classes().That().HaveNameEndingWith("Middleware")
            .And().DoNotHaveNameContaining("Test")
            .Should().BeSealed()
            .AndShould().BeInternal()
            .Because(
                "ASP.NET Core middlewares are runtime pipeline details and must be sealed and internal to prevent direct instantiation or subclassing.");

        middlewareRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 7: Concrete adapter assemblies must not expose public interfaces")]
    public void ConcreteAssemblies_ShouldNotExpose_PublicInterfaces()
    {
        IArchRule interfaceRule = Interfaces().That().ResideInAssembly(InfrastructureAssembly)
            .Or().ResideInAssembly(AspNetCoreAssembly)
            .Should().BeInternal()
            .Because(
                "All public interfaces representing ports must reside in Abstractions or Application, not in concrete adapter assemblies.")
            .WithoutRequiringPositiveResults();

        interfaceRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName =
        "🛡️ Rule 8: HTTP transport libraries must not be directly accessed by Domain or Application layers")]
    public void DomainAndApplication_ShouldNotUse_HttpTransport()
    {
        IArchRule httpGuardRule = Types().That().Are(DomainLayer).Or().Are(ApplicationLayer).Should()
            .NotDependOnAny(Types().That().ResideInNamespace("System.Net.Http"))
            .Because(
                "Domain and Application layers must remain transport-agnostic and communicate only via abstraction boundaries.");

        httpGuardRule.Check(TargetArchitecture);
    }

    [Fact(DisplayName = "🛡️ Rule 9: Configuration Options classes must be sealed")]
    public void Options_ShouldBe_Sealed()
    {
        IArchRule optionsRule = Classes().That().HaveNameEndingWith("Options")
            .And().DoNotHaveNameContaining("Test")
            .Should().BeSealed()
            .Because(
                "Configuration Options classes hold immutable system settings and must be sealed to prevent inheritance-based configuration bypasses.");

        optionsRule.Check(TargetArchitecture);
    }
}
