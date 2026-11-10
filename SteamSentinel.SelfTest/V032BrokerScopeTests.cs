using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV032BrokerScopeAsync(string root)
    {
        string originalPrivileges = ScopeTokenPrivilegeState();
        string fixture = Path.Combine(root, "v032-broker-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        string source = Path.Combine(fixture, "inert-file.bin");
        const string content = "SteamSentinel inert exact-file authorization fixture. Not executable.";
        await File.WriteAllTextAsync(source, content);
        RemediationAction action = await ScopeFileActionAsync(source, RemediationActionType.AddProgramFirewallBlock);
        RemediationPlan plan = new() { ExplicitFileTargetsRequested = true, Actions = [action] };
        BrokerEngine engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
        RemediationRunResult refused = await engine.ExecuteAsync(plan);
        Check("0.3.2 Broker client request is not authority", refused.Disposition == RemediationRunDisposition.NotStarted &&
            !refused.Success && refused.ManifestPath is null && await File.ReadAllTextAsync(source) == content);

        BrokerFileScopeAuthorization prepared = (await engine.PrepareForConfirmationAsync(plan))!;
        Check("0.3.2 Broker preparation grants no authority", ScopeRejects(() => engine.ValidateBeforeExecution(plan)));
        engine.ConfirmFileTargets(plan, prepared);
        engine.ValidateBeforeExecution(plan);
        RemediationPlan changed = new()
        {
            PlanId = plan.PlanId,
            CreatedAtUtc = plan.CreatedAtUtc,
            ExpiresAtUtc = plan.ExpiresAtUtc,
            RequestedBy = plan.RequestedBy,
            RequestedBySid = plan.RequestedBySid,
            ExplicitFileTargetsRequested = true,
            Actions = [await ScopeFileActionAsync(source, RemediationActionType.QuarantineFile)]
        };
        RemediationRunResult changedResult = await engine.ExecuteAsync(changed);
        Check("0.3.2 Broker plan-bound authority", changedResult.Disposition == RemediationRunDisposition.NotStarted &&
            changedResult.ManifestPath is null && await File.ReadAllTextAsync(source) == content);
        Check("0.3.2 Broker same-prepared replay rejected", ScopeRejects(() => engine.ConfirmFileTargets(plan, prepared)) &&
            (await engine.ExecuteAsync(plan)).Disposition == RemediationRunDisposition.NotStarted);

        RemediationPlan rollback = new() { Actions = [new() { Type = RemediationActionType.RollbackIncident, Target = Guid.NewGuid().ToString("D") }] };
        Check("0.3.2 Broker fresh rollback confirmation required", ScopeRejects(() => engine.ConfirmFileTargets(rollback, prepared)));

        BrokerFileScopeAuthorization next = (await engine.PrepareForConfirmationAsync(plan))!;
        engine.ConfirmFileTargets(plan, next);
        next.BeginExecution(plan);
        Check("0.3.2 Broker execution authority consumed once", ScopeRejects(() => next.BeginExecution(plan)) &&
            (await engine.ExecuteAsync(plan)).Disposition == RemediationRunDisposition.NotStarted);

        BrokerFileScopeAuthorization drift = (await engine.PrepareForConfirmationAsync(plan))!;
        drift.ConfirmOnce(plan);
        drift.BeginExecution(plan);
        File.Delete(source);
        await File.WriteAllTextAsync(source, content);
        bool changedIdentityRejected = false;
        using (BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(source, action.ExpectedParentIdentity))
        await using (SecureFileLease lease = SecureFileLease.Open(source))
        {
            try { await drift.VerifyLockedAsync(action, lease, parent, CancellationToken.None); }
            catch (UnauthorizedAccessException) { changedIdentityRejected = true; }
        }
        Check("0.3.2 Broker same hash different file identity rejected", changedIdentityRejected && File.Exists(source));

        bool parentPinned = false;
        using (BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(source))
        {
            try { Directory.Move(fixture, fixture + "-moved"); }
            catch (IOException) { parentPinned = true; }
            catch (UnauthorizedAccessException) { parentPinned = true; }
        }
        Check("0.3.2 Broker pins parent directory against rename", parentPinned && Directory.Exists(fixture));
        if (!Directory.Exists(fixture) && Directory.Exists(fixture + "-moved")) Directory.Move(fixture + "-moved", fixture);

        string alias = Path.Combine(fixture, "inert-hardlink.bin");
        bool hardLinkCreated = ScopeCreateHardLink(alias, source, IntPtr.Zero);
        bool hardLinkRejected = false;
        if (hardLinkCreated)
        {
            try
            {
                RemediationPlan linked = new() { ExplicitFileTargetsRequested = true, Actions = [await ScopeFileActionAsync(alias, RemediationActionType.AddProgramFirewallBlock)] };
                try { await engine.PrepareForConfirmationAsync(linked); }
                catch (UnauthorizedAccessException) { hardLinkRejected = true; }
            }
            finally { File.Delete(alias); }
        }
        Check("0.3.2 Broker hard-link aliases rejected", hardLinkCreated && hardLinkRejected && File.Exists(source));

        RemediationPlan review = new()
        {
            Actions = Enumerable.Range(1, 64).Select(index => new RemediationAction
            {
                Type = RemediationActionType.QuarantineFile,
                Target = source + "-" + index + (index == 64 ? "\u202E.exe" : string.Empty),
                IsKnownMalware = true
            }).ToList()
        };
        BrokerConfirmationRow[] rows = BrokerConfirmationWindow.BuildRows(review, null);
        Check("0.3.2 Broker complete target review", rows.Length == 64 && rows[^1].Target.Contains("64\\u202E.exe", StringComparison.Ordinal) &&
            rows.All(row => !row.Verification.Contains("known malware", StringComparison.OrdinalIgnoreCase)));
        await CaptureScopeConfirmationAsync(review, fixture);
        await ScopeExtendedAttributesAsync(fixture);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (!elevated)
        {
            Check("0.3.2 Broker complete security metadata requires privilege", ScopeRejects(() =>
            {
                using BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity();
            }));
            Check("0.3.2 Broker sensitive roundtrip requires elevation", !elevated);
            Check("0.3.2 Broker privilege state restored", ScopeTokenPrivilegeState() == originalPrivileges);
            return;
        }

        await ScopeRoundtripAsync(fixture, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            "0.3.2 Broker Windows Temp quarantine-restore", withSecurityMetadata: true);
        await ScopeRoundtripAsync(fixture, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "0.3.2 Broker Program Files quarantine-restore", withSecurityMetadata: false);
        await ScopeMetadataInheritanceMatrixAsync(fixture);
        await ScopeLateStreamAsync(fixture);
        await ScopeReadOnlyCancellationAsync(fixture);
        Check("0.3.2 Broker privilege state restored", ScopeTokenPrivilegeState() == originalPrivileges);
    }

    private static async Task<RemediationAction> ScopeFileActionAsync(string path, RemediationActionType type) => new()
    {
        Type = type,
        Target = path,
        ExpectedSha256 = await Hashing.Sha256FileAsync(path),
        ExpectedFileIdentity = FileScopeSafety.CaptureIdentity(path),
        ExpectedParentIdentity = FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(path)!, directory: true)
    };

    private static bool ScopeRejects(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidDataException or Win32Exception) { return true; }
    }

    private static async Task ScopeRoundtripAsync(string evidence, string parentRoot, string gate, bool withSecurityMetadata)
    {
        string fixture = Path.Combine(parentRoot, "SteamSentinel-ScopeTest-" + Guid.NewGuid().ToString("N"));
        string file = Path.Combine(fixture, "inert-restore-fixture.bin");
        string backup = Path.Combine(evidence, Guid.NewGuid().ToString("N") + ".quarantined");
        const string contents = "Inert Windows/Program Files restoration fixture. Never executed.";
        bool created = false;
        try
        {
            if (Directory.Exists(fixture) || File.Exists(fixture)) throw new IOException("Fixture already exists.");
            Directory.CreateDirectory(fixture);
            created = true;
            new DirectoryInfo(fixture).SetAccessControl(MachineStateSecurity.BuildProtectedDirectorySecurity());
            await File.WriteAllTextAsync(file, contents);
            File.SetCreationTimeUtc(file, new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc));
            File.SetLastWriteTimeUtc(file, new DateTime(2026, 1, 2, 3, 5, 6, DateTimeKind.Utc));
            if (withSecurityMetadata)
            {
                string sid = WindowsIdentity.GetCurrent().User!.Value;
                RawSecurityDescriptor descriptor = new($"O:{sid}G:BAD:P(A;;FA;;;{sid})(A;;FA;;;BA)S:P(AU;SA;FR;;;{sid})(ML;;NW;;;HI)");
                byte[] bytes = new byte[descriptor.BinaryLength];
                descriptor.GetBinaryForm(bytes, 0);
                using BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity();
                using BrokerRestorePrivilege restore = BrokerRestorePrivilege.EnableWhenAvailable();
                if (!ScopeSetFileSecurity(file, 1 | 2 | 4 | 8 | 0x10, bytes))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot set inert fixture security.");
                File.SetAttributes(file, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive);
            }
            Finding finding = new()
            {
                RuleId = "HEUR-STEAM-UI-PATCHER",
                Category = FindingCategory.File,
                Target = file,
                Sha256 = await Hashing.Sha256FileAsync(file),
                Score = 90,
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.QuarantineFile]
            };
            RemediationPlan plan;
            if (withSecurityMetadata)
            {
                ScanReport report = new() { Findings = [finding] };
                RemediationBatchSession batch = await new RemediationBatchPlanner(new RuleSet()).PrepareAsync(
                    [finding], report, false, inspectCandidates: null, requestExplicitFileTargets: true);
                Check("0.3.2 Broker Windows Temp explicit batch pipeline accepted", batch.Plans.Count == 1 &&
                    batch.Plans.Single().ExplicitFileTargetsRequested && batch.Plans.Single().Actions.Count == 1);
                plan = batch.Plans.Single();
            }
            else plan = await new RemediationPlanBuilder(new RuleSet()).BuildAsync([finding], false, requestExplicitFileTargets: true);
            RemediationAction action = plan.Actions.Single();
            BrokerEngine engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
            BrokerFileScopeAuthorization prepared = (await engine.PrepareForConfirmationAsync(plan))!;
            VerifiedBrokerFileTarget verified = prepared.Targets.Single();
            engine.ConfirmFileTargets(plan, prepared);
            prepared.BeginExecution(plan);
            bool persistedBeforeDeletion = false;
            QuarantineRecord record = await BrokerEngine.QuarantineExplicitFileAsync(action, prepared, backup,
                async (entry, token) =>
                {
                    persistedBeforeDeletion = File.Exists(file) && !entry.MutationConfirmed;
                    await File.WriteAllTextAsync(Path.Combine(evidence, action.ActionId + "-record.json"), JsonSerializer.Serialize(entry), token);
                }, ScopeProtectPayload, CancellationToken.None);
            bool quarantined = !File.Exists(file) && File.Exists(backup) && record.ExplicitFileAuthorization;
            await BrokerEngine.RestoreExplicitFileAsync(record, CancellationToken.None);
            BrokerFileMetadata restored;
            await using (SecureFileLease lease = SecureFileLease.OpenWithSecurity(file)) restored = BrokerFileMetadata.CaptureLocked(lease.Handle);
            Check(gate, persistedBeforeDeletion && quarantined && !File.Exists(backup) &&
                await File.ReadAllTextAsync(file) == contents && verified.Metadata == restored);
            if (withSecurityMetadata)
                Check("0.3.2 Broker restores SACL integrity owner DACL attributes times", restored.SecurityDescriptor.Contains("(ML;", StringComparison.Ordinal) &&
                    restored.SecurityDescriptor.Contains("(AU;", StringComparison.Ordinal) && restored == verified.Metadata);
        }
        catch (Exception ex)
        {
            if (ex.Data["ScopeMetadataDiagnostic"] is string diagnostic)
                await File.WriteAllTextAsync(Path.Combine(evidence, withSecurityMetadata ? "windows-metadata-diagnostic.json" : "programfiles-metadata-diagnostic.json"), diagnostic);
            Check(gate + " [" + ex.GetType().Name + ": " + ex.Message + "]", false);
        }
        finally
        {
            if (created && Path.GetFullPath(fixture).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(parentRoot)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(fixture).StartsWith("SteamSentinel-ScopeTest-", StringComparison.Ordinal) && !Validation.ContainsReparsePoint(fixture))
            {
                if (File.Exists(file)) { File.SetAttributes(file, FileAttributes.Normal); File.Delete(file); }
                if (Directory.Exists(fixture)) Directory.Delete(fixture, recursive: false);
            }
            if (File.Exists(backup)) File.Delete(backup);
        }
    }

    private static async Task ScopeMetadataInheritanceMatrixAsync(string evidence)
    {
        // Create the four inheritance models independently for each ACL, then exercise the
        // real exclusive CreateNew/copy/metadata path and reopen the completed destination.
        // Named security APIs are used only to construct the original fixtures.
        string fixture = Path.Combine(evidence, "acl-inheritance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        new DirectoryInfo(fixture).SetAccessControl(MachineStateSecurity.BuildProtectedDirectorySecurity());
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        for (int combination = 0; combination < 16; combination++)
        {
            bool daclAutoInherited = (combination & 1) != 0, saclAutoInherited = (combination & 2) != 0;
            bool daclProtected = (combination & 4) != 0, saclProtected = (combination & 8) != 0;
            string gate = $"0.3.2 Broker ACL inheritance matrix {combination:D2}";
            string source = Path.Combine(fixture, $"source-{combination:D2}.inert");
            string destination = Path.Combine(fixture, $"restored-{combination:D2}.inert");
            BrokerFileMetadata? original = null;
            try
            {
                await File.WriteAllTextAsync(source, "Inert independent DACL/SACL inheritance fixture. Never executed.");
                using (BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity())
                {
                    RawSecurityDescriptor descriptor = new($"O:{sid}G:BAD:{(daclProtected ? "P" : "")}(A;;FA;;;{sid})(A;;FA;;;BA)S:{(saclProtected ? "P" : "")}(AU;SA;FR;;;{sid})(ML;;NW;;;HI)");
                    // Legacy unprotected ACLs must retain the inherited entries. Removing
                    // them while clearing every inheritance flag makes Windows protect the
                    // ACL to preserve its meaning, which would not construct this case.
                    if (!daclAutoInherited && !daclProtected)
                        descriptor.DiscretionaryAcl = new RawSecurityDescriptor(new FileInfo(source)
                            .GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl;
                    byte[] bytes = new byte[descriptor.BinaryLength];
                    descriptor.GetBinaryForm(bytes, 0);
                    if (!ScopeSetFileSecurity(source, 1 | 2 | 4 | 8 | 0x10, bytes))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot initialize inheritance fixture.");
                    if (daclAutoInherited) ScopeSetFixtureAutoInheritance(source, descriptor.DiscretionaryAcl!, true, daclProtected);
                    if (saclAutoInherited) ScopeSetFixtureAutoInheritance(source, descriptor.SystemAcl!, false, saclProtected);
                }
                File.SetCreationTimeUtc(source, new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc));
                File.SetLastWriteTimeUtc(source, new DateTime(2026, 1, 2, 3, 5, 6, DateTimeKind.Utc));
                File.SetAttributes(source, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive);
                await using (SecureFileLease sourceLease = SecureFileLease.OpenWithSecurity(source))
                {
                    original = BrokerFileMetadata.CaptureLocked(sourceLease.Handle);
                    ControlFlags flags = new RawSecurityDescriptor(original.SecurityDescriptor).ControlFlags;
                    if (flags.HasFlag(ControlFlags.DiscretionaryAclAutoInherited) != daclAutoInherited ||
                        flags.HasFlag(ControlFlags.SystemAclAutoInherited) != saclAutoInherited ||
                        flags.HasFlag(ControlFlags.DiscretionaryAclProtected) != daclProtected ||
                        flags.HasFlag(ControlFlags.SystemAclProtected) != saclProtected)
                        throw new InvalidDataException("Fixture does not have the intended independent ACL control flags.");
                    string hash = await sourceLease.ComputeSha256Async(CancellationToken.None);
                    using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(destination);
                    using (BrokerRestorePrivilege security = BrokerRestorePrivilege.EnableSecurity())
                    using (BrokerRestorePrivilege restore = BrokerRestorePrivilege.EnableWhenAvailable())
                        await sourceLease.CopyToAsync(destination, hash, CancellationToken.None, handle => original.Apply(handle, destination));
                    await using SecureFileLease restoredLease = SecureFileLease.OpenWithSecurity(destination);
                    Check(gate, BrokerFileMetadata.CaptureLocked(restoredLease.Handle) == original &&
                        BrokerFileMetadata.CaptureLocked(sourceLease.Handle) == original &&
                        await restoredLease.ComputeSha256Async(CancellationToken.None) == hash &&
                        await sourceLease.ComputeSha256Async(CancellationToken.None) == hash);
                }
            }
            catch (Exception ex)
            {
                await File.WriteAllTextAsync(Path.Combine(evidence, $"acl-inheritance-{combination:D2}-diagnostic.json"),
                    JsonSerializer.Serialize(new
                    {
                        combination,
                        daclAutoInherited,
                        saclAutoInherited,
                        daclProtected,
                        saclProtected,
                        original,
                        error = ex.ToString(),
                        metadata = ex.Data["ScopeMetadataDiagnostic"]
                    }));
                Check(gate + " [" + ex.GetType().Name + ": " + ex.Message + "]", false);
            }
            finally
            {
                foreach (string file in new[] { source, destination })
                    if (File.Exists(file)) { File.SetAttributes(file, FileAttributes.Normal); File.Delete(file); }
            }
        }
        Directory.Delete(fixture, recursive: false);
    }

    private static void ScopeSetFixtureAutoInheritance(string path, RawAcl acl, bool discretionary, bool protect)
    {
        byte[] bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            uint information = discretionary
                ? 4 | (protect ? 0x80000000u : 0x20000000u)
                : 8 | 0x10 | (protect ? 0x40000000u : 0x10000000u);
            uint error = ScopeSetNamedSecurityInfo(path, 1, information, IntPtr.Zero, IntPtr.Zero,
                discretionary ? buffer : IntPtr.Zero, discretionary ? IntPtr.Zero : buffer);
            if (error != 0) throw new Win32Exception(checked((int)error), "Cannot set fixture inheritance model.");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static async Task ScopeLateStreamAsync(string fixture)
    {
        string file = Path.Combine(fixture, "late-stream-source.bin");
        string backup = Path.Combine(fixture, "late-stream-source.quarantined");
        await File.WriteAllTextAsync(file, "Inert source with deliberately late test stream.");
        RemediationAction action = await ScopeFileActionAsync(file, RemediationActionType.QuarantineFile);
        RemediationPlan plan = new() { ExplicitFileTargetsRequested = true, Actions = [action] };
        BrokerEngine engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
        BrokerFileScopeAuthorization prepared = (await engine.PrepareForConfirmationAsync(plan))!;
        engine.ConfirmFileTargets(plan, prepared);
        prepared.BeginExecution(plan);
        bool rejected = false;
        QuarantineRecord? recorded = null;
        try
        {
            await BrokerEngine.QuarantineExplicitFileAsync(action, prepared, backup, async (record, token) =>
            {
                recorded = record;
                await using FileStream stream = new(file + ":late-fixture", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                await stream.WriteAsync(Encoding.UTF8.GetBytes("Inert late stream retained."), token);
            }, ScopeProtectPayload, CancellationToken.None);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidDataException or Win32Exception or IOException) { rejected = true; }
        Check("0.3.2 Broker late ADS cancels deletion and retains source", rejected && File.Exists(file) &&
            recorded is { MutationConfirmed: false } && await File.ReadAllTextAsync(file + ":late-fixture") == "Inert late stream retained.");
        if (File.Exists(backup)) File.Delete(backup);
    }

    private static async Task ScopeReadOnlyCancellationAsync(string fixture)
    {
        string file = Path.Combine(fixture, "readonly-cancel.bin");
        await File.WriteAllTextAsync(file, "Inert delete-pending cancellation fixture.");
        File.SetAttributes(file, FileAttributes.ReadOnly);
        bool blockedNewStream = false;
        await using (SecureFileLease source = SecureFileLease.OpenWithSecurity(file))
        {
            source.DeleteOnClose();
            try
            {
                using FileStream stream = new(file + ":blocked", FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { blockedNewStream = true; }
            source.CancelDelete();
        }
        Check("0.3.2 Broker delete-pending blocks new ADS and cancellation retains readonly file",
            blockedNewStream && File.Exists(file) && File.GetAttributes(file).HasFlag(FileAttributes.ReadOnly));
        File.SetAttributes(file, FileAttributes.Normal);
    }

    private static async Task ScopeExtendedAttributesAsync(string fixture)
    {
        string file = Path.Combine(fixture, "inert-ea-source.bin");
        await File.WriteAllTextAsync(file, "Inert extended-attribute fixture.");
        byte[] name = Encoding.ASCII.GetBytes("SCOPE_FIXTURE");
        byte[] value = Encoding.ASCII.GetBytes("inert-data");
        byte[] ea = new byte[8 + name.Length + 1 + value.Length];
        ea[5] = checked((byte)name.Length);
        BitConverter.GetBytes(checked((ushort)value.Length)).CopyTo(ea, 6);
        name.CopyTo(ea, 8);
        value.CopyTo(ea, 9 + name.Length);
        int status;
        using (SafeFileHandle handle = File.OpenHandle(file, FileMode.Open, FileAccess.Write, FileShare.Read))
            status = ScopeNtSetEaFile(handle, out _, ea, (uint)ea.Length);
        bool refused = false;
        if (status == 0)
        {
            RemediationPlan plan = new() { ExplicitFileTargetsRequested = true, Actions = [await ScopeFileActionAsync(file, RemediationActionType.QuarantineFile)] };
            try { await new BrokerEngine(new FixtureTrustStore(null), new FixtureIncidentStateSecurity()).PrepareForConfirmationAsync(plan); }
            catch (UnauthorizedAccessException) { refused = true; }
        }
        Check("0.3.2 Broker extended attributes retain original before mutation", status == 0 && refused &&
            await File.ReadAllTextAsync(file) == "Inert extended-attribute fixture.");
    }

    private static void ScopeProtectPayload(string path) => new FileInfo(path).SetAccessControl(MachineStateSecurity.BuildProtectedFileSecurity());

    private static string ScopeTokenPrivilegeState()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        _ = ScopeGetTokenInformation(identity.AccessToken, 3, IntPtr.Zero, 0, out uint needed);
        if (needed is < 4 or > 65536) throw new InvalidDataException("Invalid privilege snapshot size.");
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)needed));
        try
        {
            if (!ScopeGetTokenInformation(identity.AccessToken, 3, buffer, needed, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            int count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > (needed - 4) / 12) throw new InvalidDataException("Invalid privilege snapshot.");
            return string.Join(";", Enumerable.Range(0, count).Select(index =>
                Marshal.ReadInt64(buffer, 4 + index * 12).ToString("X16") + ":" +
                Marshal.ReadInt32(buffer, 12 + index * 12).ToString("X8")));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static Task CaptureScopeConfirmationAsync(RemediationPlan plan, string fixture)
    {
        Exception? error = null;
        Thread thread = new(() =>
        {
            try
            {
                using BrokerConfirmationWindow window = new(plan, null);
                CreateScopeControlHandles(window);
                using Bitmap bitmap = new(window.Width, window.Height);
                window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                bitmap.Save(Path.Combine(fixture, "broker-confirmation.png"), ImageFormat.Png);
                Check("0.3.2 Broker confirmation window fits full action list", window.ClientSize.Width >= 700 && window.Controls.Count == 1);
                window.ConstrainToWorkingArea(new Rectangle(0, 0, 800, 560));
                CreateScopeControlHandles(window);
                using Bitmap compact = new(window.Width, window.Height);
                window.DrawToBitmap(compact, new Rectangle(Point.Empty, compact.Size));
                compact.Save(Path.Combine(fixture, "broker-confirmation-800x600.png"), ImageFormat.Png);
                Check("0.3.2 Broker confirmation respects 800x600 work area", window.Width <= 800 && window.Height <= 560 &&
                    window.Left >= 0 && window.Top >= 0 && window.Right <= 800 && window.Bottom <= 560);
                HashSet<int> bodyColors = [];
                for (int y = 50; y < compact.Height - 40; y += 7)
                    for (int x = 20; x < compact.Width - 20; x += 7) bodyColors.Add(compact.GetPixel(x, y).ToArgb());
                Check("0.3.2 Broker confirmation renders actual controls", bodyColors.Count >= 8);
            }
            catch (Exception ex) { error = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        Check("0.3.2 Broker confirmation renders", error is null);
        return Task.CompletedTask;
    }

    private static void CreateScopeControlHandles(System.Windows.Forms.Control control)
    {
        _ = control.Handle;
        foreach (System.Windows.Forms.Control child in control.Controls) CreateScopeControlHandles(child);
        control.PerformLayout();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateHardLinkW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ScopeCreateHardLink(string link, string existing, IntPtr security);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetFileSecurityW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ScopeSetFileSecurity(string path, uint information, byte[] descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
    private static extern uint ScopeSetNamedSecurityInfo(string path, int objectType, uint information,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [StructLayout(LayoutKind.Sequential)]
    private struct ScopeIoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll", EntryPoint = "NtSetEaFile")]
    private static extern int ScopeNtSetEaFile(SafeFileHandle file, out ScopeIoStatus ioStatus, byte[] buffer, uint length);
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "GetTokenInformation")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ScopeGetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr information, uint length, out uint returned);
}
