using System.Runtime.CompilerServices;

#if !SENTINEL_SIGNED // test-only friends; signed assemblies need a public key per entry (CS1726)
[assembly: InternalsVisibleTo("Sentinel.Tests")]
[assembly: InternalsVisibleTo("Sentinel.Tests.Unit")]
[assembly: InternalsVisibleTo("Sentinel.Tests.Integration")]
[assembly: InternalsVisibleTo("Sentinel.Tests.Security")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2")]
#endif
