using System.Diagnostics;
using System.IO;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunV0119PasswordsAsync(string output, string? worker)
    {
        output = Path.GetFullPath(output);
        if (Directory.Exists(output) || File.Exists(output))
            throw new IOException("密码回归要求新的输出目录，以保留此前证据。");
        Directory.CreateDirectory(output);
        Stopwatch elapsed = Stopwatch.StartNew();
        try
        {
            TestV0119PasswordBoundaries();
            await TestV0119PasswordsAsync(output, RuleLoader.LoadEmbedded(), worker);
        }
        catch (Exception ex)
        {
            Failures.Add("密码回归未完成：" + ex);
        }
        await JsonFile.WriteNewAsync(Path.Combine(output, "password-test-results.json"), new
        {
            version = ProductInfo.Version,
            buildIdentity = ProductInfo.BuildIdentity,
            passed = _passed,
            failed = Failures.Count,
            skipped = _skipped,
            failures = Failures,
            elapsedMs = elapsed.ElapsedMilliseconds,
            completedAtUtc = DateTimeOffset.UtcNow,
            safety = "Only generated harmless password fixtures. No remediation, installation or sample execution."
        });
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        Console.WriteLine($"密码专项：通过 {_passed}，失败 {Failures.Count}，跳过 {_skipped}。");
        return Failures.Count == 0 && _skipped == 0 ? 0 : 1;
    }
}
