#pragma warning disable CA1859 // Use concrete types for performance
#pragma warning disable CA5394 // Random is insecure (Allowed in fuzzing harnesses)
#pragma warning disable CA1031 // Do not catch general Exception (Required to catch all crashes)

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SharpFuzz;
using Sentinel.DPoP;
using Sentinel.SdJwt;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Replay;

namespace Sentinel.FuzzTests;

public static class Program
{
    public static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: dotnet run -c Release -- [target] [corpus_dir]");
            Console.WriteLine("Targets: 'dpop' or 'sdjwt'");
            return;
        }

        var target = args[0].ToLowerInvariant();
        var corpusPath = args[1];

        // გაუშვათ ჩვენი მაღალი წარმადობის ლოკალური ფაზერი
        RunProgrammaticFuzzer(target, corpusPath);
    }

    private static void RunProgrammaticFuzzer(string target, string corpusPath)
    {
        // 1. წავიკითხოთ საწყისი "თესლი"
        var seedFile = Directory.GetFiles(corpusPath, "*.txt").FirstOrDefault();
        if (seedFile == null)
        {
            Console.WriteLine($"Error: No seed file found in corpus directory: {corpusPath}");
            return;
        }

        var seedBytes = File.ReadAllBytes(seedFile);
        var crashDir = Path.Combine(corpusPath, "crashes");
        Directory.CreateDirectory(crashDir);

        Console.WriteLine($"=== STARTING SENTINEL PURE .NET GENERATIVE FUZZER ===");
        Console.WriteLine($"Target: {target.ToUpperInvariant()}");
        Console.WriteLine($"Corpus Path: {corpusPath}");
        Console.WriteLine($"Crashes Saved To: {crashDir}");
        Console.WriteLine("Fuzzing is running... Press Ctrl+C to stop.");
        Console.WriteLine("-----------------------------------------------------");

        // 2. მოვამზადოთ სამიზნე სერვისები
        var replayCache = new FakeInMemoryJtiCache();
        var options = Microsoft.Extensions.Options.Options.Create(new DPoPOptions
        {
            ProofLifetimeSeconds = 300,
            AllowedClockSkewSeconds = 60
        });
        IDpopProofValidator dpopValidator = new DpopProofValidator(replayCache, options);
        var presenter = new SdJwtPresenter(new FakeTokenValidator(), new SdJwtVerificationOptions());
        var targetUri = new Uri("https://api.sentinel.io/v1/auth");

        long execCount = 0;
        long crashCount = 0;
        var sw = Stopwatch.StartNew();
        var rnd = new Random();

        // 3. ფაზინგის უსწრაფესი გენერაციული ციკლი
        while (true)
        {
            // მოვახდინოთ ბაიტების მუტაცია
            var mutated = Mutate(seedBytes, rnd);

            try
            {
                execCount++;
                if (target == "dpop")
                {
                    var dpopHeader = Encoding.UTF8.GetString(mutated);
                    var request = new DpopValidationRequest(dpopHeader, "POST", targetUri);
                    _ = dpopValidator.ValidateAsync(request).GetAwaiter().GetResult();
                }
                else
                {
                    var presentation = Encoding.UTF8.GetString(mutated);
                    _ = presenter.VerifyPresentationAsync(presentation, "sentinel-api", null, CancellationToken.None)
                        .GetAwaiter().GetResult();
                }
            }
            catch (Exception ex) when (
                ex is JsonException ||
                ex is FormatException ||
                ex is SecurityTokenException ||
                ex is CryptographicException)
            {
                // მოსალოდნელი შეცდომები ფორმატის გამო - უგულებელყოფა
            }
            catch (Exception ex)
            {
                // ⚠️ კრიტიკული: ვიპოვეთ გაუთვალისწინებელი კრაში (ბაგი / ხვრელი!)
                crashCount++;
                var crashFile = Path.Combine(crashDir, $"crash_{Guid.NewGuid():N}.txt");
                File.WriteAllBytes(crashFile, mutated);

                Console.WriteLine($"\n[CRASH DETECTED] Unexpected exception: {ex.GetType().Name}!");
                Console.WriteLine($"Exploit payload saved to: {crashFile}");
                Console.WriteLine($"Exception Details: {ex.Message}\n");
            }

            // ყოველ 10,000 ოპერაციაში ვბეჭდავთ სტატისტიკას ეკრანზე
            if (execCount % 10000 == 0)
            {
                var rps = execCount / sw.Elapsed.TotalSeconds;
                Console.Write($"\rExecutions: {execCount:N0} | Crashes: {crashCount} | Speed: {rps:N0} exec/s");
            }
        }
    }

    // მუტაციის ალგორითმი (Bit-flipping, Byte replacement, Truncation)
    private static byte[] Mutate(byte[] original, Random rnd)
    {
        var copy = (byte[])original.Clone();
        var mutations = rnd.Next(1, 5); // 1-დან 4-მდე სუპერ-სწრაფი მუტაცია

        for (int i = 0; i < mutations; i++)
        {
            var mutationType = rnd.Next(0, 3);
            var index = rnd.Next(0, copy.Length);

            switch (mutationType)
            {
                case 0: // Bit flip (XOR)
                    copy[index] ^= (byte)rnd.Next(1, 256);
                    break;
                case 1: // ბაიტის სრული ჩანაცვლება
                    copy[index] = (byte)rnd.Next(0, 256);
                    break;
                case 2: // შეკვეცა (Truncation)
                    var newSize = rnd.Next(1, copy.Length);
                    Array.Resize(ref copy, newSize);
                    break;
            }
        }

        return copy;
    }

    private sealed class FakeInMemoryJtiCache : IJtiReplayCache
    {
        public Task<bool> TryMarkUsedAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
            => Task.FromResult(true);

        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeTokenValidator : ISdJwtTokenValidator
    {
        private static readonly JsonWebTokenHandler TokenHandler = new();
        public Task<SdJwtIssuerTokenValidationResult> ValidateIssuerTokenAsync(string issuerJwt, string expectedAudience, CancellationToken cancellationToken = default) =>
            Task.FromResult(SdJwtIssuerTokenValidationResult.Success(TokenHandler.ReadJsonWebToken(issuerJwt)));
    }
}

#pragma warning restore CA1859
#pragma warning restore CA5394
#pragma warning restore CA1031
