using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

namespace Sentinel.Benchmarks;

public static class Program
{
    public static void Main(string[] args)
    {
        var config = ManualConfig.Create(DefaultConfig.Instance)
            .WithOptions(ConfigOptions.DisableOptimizationsValidator);

        _ = BenchmarkRunner.Run<DpopValidatorBenchmark>(config, args);
        _ = BenchmarkRunner.Run<SdJwtPresenterBenchmark>(config, args);
    }
}
