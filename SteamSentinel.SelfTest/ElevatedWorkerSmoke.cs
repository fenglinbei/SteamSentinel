using System.IO;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.App.Native;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static string DevelopmentWorkerPath() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
        "../../../../SteamSentinel.ArchiveWorker/bin/Release/net10.0-windows10.0.19041.0/SteamSentinel.ArchiveWorker.exe"));

    // Explicit developer utility, not included in release payloads. Fixed scope:
    // one Low handshake and only self-created inert text/ZIP. Never invokes Broker.
    private static async Task<int> RunElevatedWorkerSmokeAsync()
    {
        string resultsRoot = Path.GetFullPath(AppPaths.ResultsRoot);
        if (!ElevationContext.Read().IsElevated || !Directory.Exists(resultsRoot) ||
            Validation.ContainsReparsePoint(resultsRoot))
            return 2;
        string id = "v018-worker-smoke-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N");
        string evidenceRoot = Path.Combine(resultsRoot, id);
        // Create a new protected evidence directory, never change an existing ACL.
        if (Directory.Exists(evidenceRoot) || File.Exists(evidenceRoot)) return 2;
        DirectorySecurity security = new();
        security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
        DirectoryInfo created = new(evidenceRoot);
        created.Create(security);
        if (Validation.ContainsReparsePoint(evidenceRoot) || !InstallationSecurity.CheckAcl(created).IsProtected) return 2;
        string evidencePath = Path.Combine(evidenceRoot, "result.json");
        string fixtureRoot = Path.Combine(evidenceRoot, "fixtures");
        string? working = null;
        Dictionary<string, object?> evidence = new()
        {
            ["Version"] = ProductInfo.Version,
            ["StartedAtUtc"] = DateTimeOffset.UtcNow,
            ["ParentIntegrity"] = ProcessIntegrity.GetCurrent().ToString(),
            ["Elevation"] = ElevationContext.Read(),
            ["Scope"] = "Low handshake and generated inert text/ZIP only",
            ["Passed"] = false
        };
        try
        {
            Directory.CreateDirectory(fixtureRoot);
            string workerPath = DevelopmentWorkerPath();
            evidence["WorkerPath"] = workerPath;
            evidence["WorkerDllSha256"] = await Hashing.Sha256FileAsync(Path.ChangeExtension(workerPath, ".dll"));
            evidence["AppDllSha256"] = await Hashing.Sha256FileAsync(typeof(ArchiveWorkerClient).Assembly.Location);
            using var caller = TokenProbe.OpenCurrent();
            byte[] originalDacl = TokenProbe.Dacl(caller);
            evidence["ParentOwner"] = TokenProbe.Sid(caller, 4);
            using var restricted = RestrictedProcess.CreateLowIntegrityToken();
            evidence["RestrictedOwner"] = TokenProbe.Sid(restricted, 4);
            evidence["RestrictedIntegritySid"] = TokenProbe.Sid(restricted, 25);
            using (WindowsIdentity restrictedIdentity = new(restricted.DangerousGetHandle()))
                evidence["RestrictedIsAdministrator"] = new WindowsPrincipal(restrictedIdentity).IsInRole(WindowsBuiltInRole.Administrator);

            working = Path.Combine(AppPaths.WorkerTemporaryRoot, id);
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(45));
            using (JobObject job = new())
            using (RestrictedProcess worker = RestrictedProcess.Start(workerPath, working, job))
            {
                string? line = await worker.StandardOutput.ReadLineAsync(timeout.Token);
                WorkerMessage? ready = line is null ? null : JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
                evidence["Handshake"] = ready;
                worker.StandardInput.Close();
                await worker.WaitForExitAsync(timeout.Token);
                evidence["HandshakeEofExit"] = worker.ExitCode;
                evidence["HandshakeStderr"] = await worker.StandardError.ReadToEndAsync(timeout.Token);
                if (ready?.Type != WorkerMessageTypes.Ready || ready.Containment != "Low" || worker.ExitCode != 2)
                    throw new InvalidOperationException("Elevated parent did not complete a Low handshake.");
            }

            string textFile = Path.Combine(fixtureRoot, "harmless.txt");
            await File.WriteAllTextAsync(textFile, "SteamSentinel harmless startup regression fixture.");
            string zipFile = Path.Combine(fixtureRoot, "harmless.zip");
            using (ZipArchive zip = ZipFile.Open(zipFile, ZipArchiveMode.Create))
            using (StreamWriter writer = new(zip.CreateEntry("readme.txt").Open()))
                await writer.WriteAsync("Harmless archive fixture, no executable code.");
            ScanOptions options = new()
            {
                Mode = ScanMode.Custom,
                IncludeSystem = false,
                IncludeSteam = false,
                IncludeWorkshop = false,
                UseAmsi = false,
                CustomRoots = [textFile, zipFile]
            };
            ScanReport report = await new ArchiveWorkerClient(workerPath).RunAsync(options,
                (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)), null, timeout.Token);
            evidence["Scan"] = report;
            evidence["ParentDaclUnchanged"] = TokenProbe.Dacl(caller).SequenceEqual(originalDacl);
            evidence["Passed"] = report.Coverage == ScanCoverage.Complete && report.Metrics.FilesVisited >= 2 &&
                report.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware) && (bool)evidence["ParentDaclUnchanged"]!;
        }
        catch (Exception ex) { evidence["Error"] = ex.ToString(); }
        finally
        {
            // Only newly generated directories, within verified exact parents.
            foreach (string path in new[] { fixtureRoot, working }.OfType<string>())
            {
                try
                {
                    string parent = Path.GetDirectoryName(path)!;
                    if (((parent.Equals(evidenceRoot, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(path) == "fixtures") ||
                         (parent.Equals(Path.GetFullPath(AppPaths.WorkerTemporaryRoot), StringComparison.OrdinalIgnoreCase) && Path.GetFileName(path) == id)) &&
                        Directory.Exists(path) && !Validation.ContainsReparsePoint(path))
                        Directory.Delete(path, true);
                }
                catch (Exception ex) { evidence["CleanupError"] = ex.Message; }
            }
            evidence["CompletedAtUtc"] = DateTimeOffset.UtcNow;
            await JsonFile.WriteNewAsync(evidencePath, evidence);
        }
        return (bool)evidence["Passed"]! ? 0 : 1;
    }
}
