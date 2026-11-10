using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private sealed record ScopeAcceptanceCheck(string name, bool passed);
    private static List<ScopeAcceptanceCheck>? _scopeAcceptanceChecks;

    // Explicit release acceptance uses inert fixtures only. The final run must use
    // the signed release DLLs and standard hosts, with matching commit/tree identity.
    private static async Task<int> RunV032ScopeAuthorizationAsync(string output, string? commit, string? tree)
    {
        if (Directory.Exists(output) || File.Exists(output) || Validation.ContainsReparsePoint(Path.GetDirectoryName(output)!))
            throw new IOException("A new physical acceptance directory is required.");
        Directory.CreateDirectory(output);
        Stopwatch elapsed = Stopwatch.StartNew();
        _scopeAcceptanceChecks = [];
        bool corePassed = false, brokerPassed = false, uiPassed = false;
        string? error = null;
        string app = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Standard.exe");
        string broker = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Broker.Standard.exe");
        string core = Path.Combine(AppContext.BaseDirectory, "SteamSentinel.Core.dll");
        string appAssembly = typeof(SteamSentinel.App.App).Assembly.Location;
        string brokerAssembly = typeof(SteamSentinel.Broker.BrokerEngine).Assembly.Location;
        bool finalIdentity = commit is not null || tree is not null;
        try
        {
            if (finalIdentity)
            {
                Check("scope_release_identity_matches_exact_commit", commit is { Length: 40 } && commit.All(Uri.IsHexDigit) &&
                    tree is { Length: 40 } && tree.All(Uri.IsHexDigit) && ProductInfo.BuildIdentity == $"{ProductInfo.Version}+{commit}.preview");
                using WindowsIdentity account = WindowsIdentity.GetCurrent();
                Check("scope_release_sensitive_positive_fixtures_run_elevated", new WindowsPrincipal(account).IsInRole(WindowsBuiltInRole.Administrator));
                Check("scope_release_standard_hosts_and_core_present", File.Exists(app) && File.Exists(broker) && File.Exists(core));
            }
            int before = Failures.Count;
            await TestV032CoreScopeAsync(output);
            corePassed = Failures.Count == before;
            before = Failures.Count;
            await TestV032BrokerScopeAsync(output);
            brokerPassed = Failures.Count == before;
            if (finalIdentity)
                Check("scope_release_both_sensitive_directory_roundtrips_verified",
                    _scopeAcceptanceChecks.Any(check => check.name == "0.3.2 Broker Windows Temp quarantine-restore" && check.passed) &&
                    _scopeAcceptanceChecks.Any(check => check.name == "0.3.2 Broker Program Files quarantine-restore" && check.passed));
            before = Failures.Count;
            uiPassed = RunV032ScopeUi(Path.Combine(output, "ui")) == 0 && Failures.Count == before;
            Check("scope_all_regression_groups_completed", corePassed && brokerPassed && uiPassed);
        }
        catch (Exception ex)
        {
            error = ex.GetType().Name;
            Check("scope_acceptance_completed_without_exception", false);
            Console.Error.WriteLine(ex);
        }
        finally
        {
            List<ScopeAcceptanceCheck> checks = _scopeAcceptanceChecks!;
            _scopeAcceptanceChecks = null;
            bool passed = corePassed && brokerPassed && uiPassed && checks.All(check => check.passed);
            bool Has(string name) => checks.Any(check => check.name == name && check.passed);
            await JsonFile.WriteNewAsync(Path.Combine(output, "SCOPE-AUTHORIZATION-RESULTS.json"), new
            {
                schema = "SteamSentinel.ScopeAuthorizationAcceptance/1",
                version = ProductInfo.Version,
                buildIdentity = ProductInfo.BuildIdentity,
                sourceCommit = commit,
                sourceTree = tree,
                passed = checks.Count(check => check.passed),
                failed = checks.Count(check => !check.passed),
                skipped = _skipped,
                elapsedMs = elapsed.ElapsedMilliseconds,
                exactFileIdentityVerified = passed && Has("0.3.2 Broker same hash different file identity rejected"),
                sensitivePathConsentVerified = passed && Has("0.3.2 Broker Windows Temp quarantine-restore") && Has("0.3.2 Broker Program Files quarantine-restore"),
                planBoundAuthorizationVerified = passed && Has("0.3.2 Broker plan-bound authority"),
                replayRejected = passed && Has("0.3.2 Broker same-prepared replay rejected"),
                recoveryRequiresFreshConfirmationVerified = passed && Has("0.3.2 Broker fresh rollback confirmation required"),
                limitsShownBeforeConfirmationVerified = passed && uiPassed,
                noAdditionalAuthorizationPopupVerified = passed && uiPassed,
                existingConfirmationCountUnchanged = passed && uiPassed,
                additionalAuthorizationPopups = 0,
                additionalBatchConfirmations = 0,
                appFile = Path.GetFileName(app),
                appSha256 = File.Exists(app) ? await Hashing.Sha256FileExclusiveAsync(app) : null,
                brokerFile = Path.GetFileName(broker),
                brokerSha256 = File.Exists(broker) ? await Hashing.Sha256FileExclusiveAsync(broker) : null,
                coreFile = Path.GetFileName(core),
                coreSha256 = File.Exists(core) ? await Hashing.Sha256FileExclusiveAsync(core) : null,
                appAssemblyFile = Path.GetFileName(appAssembly),
                appAssemblySha256 = await Hashing.Sha256FileExclusiveAsync(appAssembly),
                brokerAssemblyFile = Path.GetFileName(brokerAssembly),
                brokerAssemblySha256 = await Hashing.Sha256FileExclusiveAsync(brokerAssembly),
                tests = checks,
                error,
                completedAtUtc = DateTimeOffset.UtcNow
            });
        }
        return Failures.Count == 0 && corePassed && brokerPassed && uiPassed ? 0 : 1;
    }
}
