using System.Diagnostics;
using System.IO;
using SteamSentinel.App;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Diagnostic subset for integration after the separately expensive legacy path corpus.
    // The release pipeline still runs the complete default suite without this shortcut.
    private static async Task<int> RunV020PostLegacyAsync(string outputDirectory)
    {
        string output = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(output);
        string root = Path.Combine(output, "fixtures-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Stopwatch elapsed = Stopwatch.StartNew();
        try
        {
            RuleSet rules = RuleLoader.LoadEmbedded();
            await TestV0117UiAsync(root);
            await TestPhase2MsiAsync(root, rules);
            TestPhase2Discovery();
            TestPhase2SourceBounds();
            TestPhase2RelatedBatch();
            await TestPhase2PipelineAsync(root);
            await TestPhase2RelatedSignatureAsync(root);
            await TestPhase2RelatedPresentationAsync(root);
            await TestPhase3DependenciesAsync(root);
            TestPhase3CertificateRepair();
            TestPhase3CertificateAbi();
            TestPhase3ProxyRepair();
            await TestPhase3ConfigurationBrokerAsync();
            await TestPhase3CasesAsync(root);
            await TestPhase3CaseExportAsync(root);
            await TestV0117ScannerAsync(root);
            await TestV0117SecurityAsync(root);
            TestV0117ReleaseEngineering();
            await TestWorkerProtocolAsync(root);
            await TestRestrictedWorkerClientAsync(root);
            await TestPlanBuilderAsync(root, rules);
            await TestBoundBrokerPlanAsync();
            await TestSecureFileLeaseAsync(root);
            await TestReportExportAsync(root, rules);
            Check("Steam 进程门禁不误判 SteamSentinel", MainWindow.IsSteamClientProcessName("steam") &&
                MainWindow.IsSteamClientProcessName("steamwebhelper") && !MainWindow.IsSteamClientProcessName("SteamSentinel"));
            TestDisplayLabels();
            TestSteamDiscovery();
            await TestSystemScannerReadOnlyAsync(rules);
        }
        catch (Exception ex)
        {
            Failures.Add("集成子集发生未处理异常：" + ex);
        }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "integration-results.json"), new
        {
            Passed = _passed,
            Failed = Failures.Count,
            Failures,
            BuildIdentity = ProductInfo.BuildIdentity,
            ElapsedMilliseconds = elapsed.ElapsedMilliseconds,
            CompletedAtUtc = DateTimeOffset.UtcNow
        });
        Console.WriteLine($"V020_INTEGRATION_PASS={_passed};FAIL={Failures.Count}");
        foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
        return Failures.Count == 0 ? 0 : 1;
    }
}
