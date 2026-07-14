using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using Reqnroll;
using Sentinel.Tests.Shared.Fixtures;

namespace Sentinel.Tests.Acceptance.Steps;

[Binding]
public static class AcceptanceTestHooks
{
    private const int ApiPort = 5260;
    private const int RedisPort = 6379;
    private const int KeycloakPort = 8443;

    private static readonly SemaphoreSlim InitializationLock = new(1, 1);
    private static readonly ConcurrentQueue<string> ProcessOutputBuffer = new();
    private static readonly ConcurrentQueue<string> ProcessErrorBuffer = new();
    private static Process? _apiProcess;

    [BeforeTestRun]
    public static async Task StartApiHostAsync()
    {
        await InitializationLock.WaitAsync();
        try
        {
            var solutionRoot = FindSolutionRoot();

            await StartDockerInfrastructureAsync(solutionRoot);

            var infraReady = await WaitForPortActiveAsync(RedisPort, TimeSpan.FromSeconds(60))
                             && await WaitForPortActiveAsync(KeycloakPort, TimeSpan.FromSeconds(60));

            if (!infraReady)
            {
                throw new TimeoutException(
                    "Required Docker infrastructure (Redis/Keycloak) failed to become active within 60 seconds.");
            }

            if (IsPortInUse(ApiPort))
            {
                return;
            }

            var projectPath = Path.Combine(solutionRoot, "samples", "Sentinel.Sample.MinimalApi",
                "Sentinel.Sample.MinimalApi.csproj");
            var pubKeyBytes = TestTokenIssuer.AuthorityKey.ExportSubjectPublicKeyInfo();
            var testPublicKeyBase64 = Convert.ToBase64String(pubKeyBytes);

            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments =
                    $"run --project \"{projectPath}\" -c Release --no-launch-profile --urls \"http://127.0.0.1:{ApiPort}\" -- --Security:TestPublicKey={testPublicKeyBase64} --environment Development",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = solutionRoot
            };

            startInfo.EnvironmentVariables["Security__TestPublicKey"] = testPublicKeyBase64;
            startInfo.EnvironmentVariables["ConnectionStrings__Redis"] = "127.0.0.1:6379";
            startInfo.EnvironmentVariables["Sentinel__Redis__EndPoint"] = "127.0.0.1:6379";
            startInfo.EnvironmentVariables["ASPNETCORE_ENVIRONMENT"] = "Development";
            startInfo.EnvironmentVariables["DPoP__AllowedAlgorithms__0"] = "PS256";
            startInfo.EnvironmentVariables["DPoP__AllowedAlgorithms__1"] = "ES256";
            startInfo.EnvironmentVariables["DPoP__AllowedClockSkewSeconds"] = "10";
            startInfo.EnvironmentVariables["DPoP__ProofLifetimeSeconds"] = "60";

            _apiProcess = new Process { StartInfo = startInfo };

            _apiProcess.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    ProcessOutputBuffer.Enqueue(e.Data);
                }
            };
            _apiProcess.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    ProcessErrorBuffer.Enqueue(e.Data);
                }
            };

            if (!_apiProcess.Start())
            {
                throw new InvalidOperationException("Failed to initiate the dotnet run process.");
            }

            _apiProcess.BeginOutputReadLine();
            _apiProcess.BeginErrorReadLine();

            var apiReady = await WaitForPortActiveAsync(ApiPort, TimeSpan.FromSeconds(90));

            if (!apiReady)
            {
                await TeardownHostAndContainersAsync(solutionRoot);

                var diagnostics = CompileDiagnosticReport();
                throw new TimeoutException(
                    $"Self-hosted Minimal API failed to bind to port {ApiPort} within 90 seconds. System state is unresolved.\n\nDiagnostics Report:\n{diagnostics}");
            }
        }
        finally
        {
            InitializationLock.Release();
        }
    }

    [AfterTestRun]
    public static async Task StopApiHostAsync()
    {
        await InitializationLock.WaitAsync();
        try
        {
            var solutionRoot = FindSolutionRoot();

            var diagnostics = CompileDiagnosticReport();
            Console.WriteLine(diagnostics);

            await TeardownHostAndContainersAsync(solutionRoot);
        }
        finally
        {
            InitializationLock.Release();
        }
    }

    private static async Task TeardownHostAndContainersAsync(string workingDirectory)
    {
        if (_apiProcess != null)
        {
            await KillProcessTreeAsync(_apiProcess);
            _apiProcess.Dispose();
            _apiProcess = null;
        }

        await StopDockerContainersAsync(workingDirectory);
    }

    private static async Task StartDockerInfrastructureAsync(string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = "compose up -d redis keycloak",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                if (process.ExitCode != 0)
                {
                    startInfo.FileName = "docker-compose";
                    startInfo.Arguments = "up -d redis keycloak";
                    using var legacyProcess = Process.Start(startInfo);
                    if (legacyProcess != null)
                    {
                        await legacyProcess.WaitForExitAsync();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Docker daemon is unreachable. Verify Docker Desktop is active.", ex);
        }
    }

    private static async Task StopDockerContainersAsync(string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = "compose down -v",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                if (process.ExitCode != 0)
                {
                    startInfo.FileName = "docker-compose";
                    startInfo.Arguments = "down -v";
                    using var legacyProcess = Process.Start(startInfo);
                    if (legacyProcess != null)
                    {
                        await legacyProcess.WaitForExitAsync();
                    }
                }
            }
        }
#pragma warning disable CA1031
        catch
        {
            // Suppress errors during teardown to avoid masking test results
        }
#pragma warning restore CA1031
    }

    private static async Task<bool> WaitForPortActiveAsync(int port, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            while (!cts.IsCancellationRequested)
            {
                if (IsPortInUse(port))
                {
                    return true;
                }

                await Task.Delay(200, cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }

        return false;
    }

    private static bool IsPortInUse(int port)
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var activeListeners = properties.GetActiveTcpListeners();
        return activeListeners.Any(endpoint => endpoint.Port == port);
    }

    private static string FindSolutionRoot()
    {
        var currentDir = AppDomain.CurrentDomain.BaseDirectory;
        var directory = new DirectoryInfo(currentDir);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        if (directory == null)
        {
            throw new DirectoryNotFoundException("Could not locate solution root containing 'Sentinel.slnx'");
        }

        return directory.FullName;
    }

    private static async Task KillProcessTreeAsync(Process process)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            using var killProcess = Process.Start(new ProcessStartInfo
            {
                FileName = "taskkill",
                Arguments = $"/T /F /PID {process.Id}",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            if (killProcess != null)
            {
                await killProcess.WaitForExitAsync();
            }
        }
        else
        {
            try
            {
                process.Kill(true);
            }
            catch (InvalidOperationException)
            {
            }
            catch (Win32Exception)
            {
            }
        }
    }

    private static string CompileDiagnosticReport()
    {
        var report = new StringBuilder();
        report.AppendLine("==================================================");
        report.AppendLine("          API HOST STARTUP DIAGNOSTICS            ");
        report.AppendLine("==================================================");

        report.AppendLine("\n--- STANDARD OUTPUT (STDOUT) ---");
        foreach (var line in ProcessOutputBuffer)
        {
            report.AppendLine(line);
        }

        report.AppendLine("\n--- STANDARD ERROR (STDERR) ---");
        foreach (var line in ProcessErrorBuffer)
        {
            report.AppendLine(line);
        }

        report.AppendLine("==================================================");

        return report.ToString();
    }
}
