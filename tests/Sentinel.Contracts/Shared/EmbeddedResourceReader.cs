using System.Reflection;
using System.Text;

namespace Sentinel.Contracts.Shared;

/// <summary>
///     Loads embedded contract artifacts (JSON schemas, OpenAPI baselines).
/// </summary>
public static class EmbeddedResourceReader
{
    public static string Read(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (name.EndsWith($".{resourceName}", StringComparison.Ordinal))
            {
                using var stream = assembly.GetManifestResourceStream(name)
                    ?? throw new InvalidOperationException($"Embedded resource '{resourceName}' is not readable.");
                using var reader = new StreamReader(stream, Encoding.UTF8);
                return reader.ReadToEnd();
            }
        }

        throw new FileNotFoundException($"Embedded resource '{resourceName}' was not found.", resourceName);
    }
}