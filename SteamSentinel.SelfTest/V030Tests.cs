using System.IO;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030Async(string root)
    {
        await TestV030ZipNamesAsync(root);
        await TestV030DiscoveryAsync(root);
        await TestV030AmsiDiagnosticsAsync(root);
        await TestV030Step4Async(root);
    }

    private static async Task<int> RunV030Async(string root)
    {
        Directory.CreateDirectory(root);
        try
        {
            await TestV030Async(root);
            await TestV020PublishedMemberIdentityAsync(root);
            TestV0117ReleaseEngineering();
        }
        catch (Exception exception) { Failures.Add(exception.ToString()); Console.Error.WriteLine(exception); }
        await JsonFile.WriteAtomicAsync(Path.Combine(root, "results.json"), new
        {
            passed = _passed,
            failed = Failures.Count,
            skipped = _skipped,
            failures = Failures,
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            completedAtUtc = DateTimeOffset.UtcNow
        });
        Console.WriteLine($"V030_PASS={_passed};FAIL={Failures.Count};SKIP={_skipped}");
        return Failures.Count == 0 ? 0 : 1;
    }
}
