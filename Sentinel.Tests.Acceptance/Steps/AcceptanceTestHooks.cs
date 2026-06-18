using System.Diagnostics;
using System.Net.NetworkInformation;
using Reqnroll;

namespace Sentinel.Tests.Acceptance.Steps;

[Binding]
public static class AcceptanceTestHooks
{
    private static Process? _apiProcess;

    [BeforeTestRun]
    public static void StartApiHost()
    {
        const int apiPort = 5260;
        const int redisPort = 6379;
        const int keycloakPort = 8443;

        var currentDir = AppDomain.CurrentDomain.BaseDirectory;
        var directory = new DirectoryInfo(currentDir);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        if (directory == null)
        {
            throw new DirectoryNotFoundException("Could not find solution root directory containing 'Sentinel.slnx'");
        }

        StartDockerContainers(directory.FullName);

        var infraReady = WaitForPortActive(redisPort, TimeSpan.FromSeconds(30))
                         && WaitForPortActive(keycloakPort, TimeSpan.FromSeconds(30));

        if (!infraReady)
        {
            throw new TimeoutException(
                "Required Docker infrastructure (Redis/Keycloak) failed to start within the SLA window.");
        }

        if (IsPortActive(apiPort))
        {
            return;
        }

        var projectPath = Path.Combine(directory.FullName, "samples", "Sentinel.Sample.MinimalApi",
            "Sentinel.Sample.MinimalApi.csproj");

        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{projectPath}\" -c Release --urls \"http://127.0.0.1:{apiPort}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = directory.FullName
        };

        _apiProcess = Process.Start(startInfo);

        var apiReady = WaitForPortActive(apiPort, TimeSpan.FromSeconds(15));

        if (!apiReady)
        {
            _apiProcess?.Kill(true);
            throw new TimeoutException(
                $"Self-hosted Minimal API failed to start on port {apiPort} within the SLA window.");
        }
    }

    [AfterTestRun]
    public static void StopApiHost()
    {
        if (_apiProcess != null && !_apiProcess.HasExited)
        {
            _apiProcess.Kill(true);
            _apiProcess.Dispose();
        }

        var currentDir = AppDomain.CurrentDomain.BaseDirectory;
        var directory = new DirectoryInfo(currentDir);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        if (directory != null)
        {
            StopDockerContainers(directory.FullName);
        }
    }

    private static void StartDockerContainers(string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = "compose up -d redis keycloak",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        try
        {
            using var process = Process.Start(startInfo);
            process?.WaitForExit();
            if (process?.ExitCode != 0)
            {
                startInfo.FileName = "docker-compose";
                startInfo.Arguments = "up -d redis keycloak";
                using var legacyProcess = Process.Start(startInfo);
                legacyProcess?.WaitForExit();
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to run Docker. Make sure Docker Desktop is active and running.",
                ex);
        }
    }

    private static void StopDockerContainers(string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = "compose down",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };


        using var process = Process.Start(startInfo);
        process?.WaitForExit();
        if (process?.ExitCode != 0)
        {
            startInfo.FileName = "docker-compose";
            startInfo.Arguments = "down";
            using var legacyProcess = Process.Start(startInfo);
            legacyProcess?.WaitForExit();
        }
    }

    private static bool WaitForPortActive(int port, TimeSpan timeout)
    {
        var startedAt = DateTime.UtcNow;
        while (DateTime.UtcNow - startedAt < timeout)
        {
            if (IsPortActive(port))
            {
                return true;
            }

            Thread.Sleep(250);
        }

        return false;
    }

    private static bool IsPortActive(int port)
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var activeListeners = properties.GetActiveTcpListeners();
        return activeListeners.Any(endpoint => endpoint.Port == port);
    }
}
