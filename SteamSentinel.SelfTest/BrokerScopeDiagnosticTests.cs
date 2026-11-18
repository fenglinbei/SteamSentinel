using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private sealed record ScopeDiagnosticCheck(string name, bool passed);
    private static List<ScopeDiagnosticCheck>? _scopeDiagnosticChecks;
    private static bool _scopeNativeMetadataVerified;

    private static void CheckScopeDiagnostic(string name, bool passed)
    {
        _scopeDiagnosticChecks?.Add(new(name, passed));
        Check("scope diagnostic " + name, passed);
    }

    private static async Task<int> RunBrokerScopeDiagnosticsAsync(string output)
    {
        if (Directory.Exists(output) || File.Exists(output) || Validation.ContainsReparsePoint(Path.GetDirectoryName(output)!))
            throw new IOException("A new physical diagnostic test directory is required.");
        Directory.CreateDirectory(output);
        Stopwatch elapsed = Stopwatch.StartNew();
        _scopeDiagnosticChecks = [];
        try { await TestBrokerScopeDiagnosticsAsync(output); }
        catch (Exception ex)
        {
            CheckScopeDiagnostic("completed without exception", false);
            Console.Error.WriteLine(ex);
        }
        List<ScopeDiagnosticCheck> checks = _scopeDiagnosticChecks;
        _scopeDiagnosticChecks = null;
        await JsonFile.WriteNewAsync(Path.Combine(output, "SCOPE-DIAGNOSTIC-RESULTS.json"), new
        {
            schema = "SteamSentinel.ScopeDiagnosticAcceptance/1",
            passed = checks.Count(check => check.passed),
            failed = checks.Count(check => !check.passed),
            skipped = _skipped,
            nativeMetadataVerified = _scopeNativeMetadataVerified,
            elapsedMs = elapsed.ElapsedMilliseconds,
            tests = checks,
            completedAtUtc = DateTimeOffset.UtcNow
        });
        return checks.All(check => check.passed) ? 0 : 1;
    }

    // Only inert files below this new fixture directory are changed. These checks do
    // not invoke the Broker entry point, execute samples, or modify machine state.
    private static async Task TestBrokerScopeDiagnosticsAsync(string root)
    {
        _scopeNativeMetadataVerified = false;
        string fixture = Path.Combine(root, "scope-diagnostics-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        string file = Path.Combine(fixture, "identity-fixture.txt");
        const string contents = "Inert file identity and metadata diagnostic fixture. Never executed.";
        await File.WriteAllTextAsync(file, contents);

        RemediationAction original = await DiagnosticFileActionAsync(file, RemediationActionType.AddProgramFirewallBlock);
        string otherParent = Path.Combine(fixture, "other-parent");
        Directory.CreateDirectory(otherParent);
        RemediationAction wrongParent = await DiagnosticFileActionAsync(file, RemediationActionType.AddProgramFirewallBlock,
            parentIdentity: FileScopeSafety.CaptureIdentity(otherParent, directory: true));
        Exception? failure = await CaptureScopeDiagnosticAsync(async () =>
            _ = await PrepareScopeDiagnosticAsync(wrongParent));
        CheckScopeDiagnostic("prepare parent identity identifies expected and actual values",
            DiagnosticIs(failure, "Scope.Diagnostic.Prepare.ParentIdentity") &&
            failure!.Message.Contains(wrongParent.ExpectedParentIdentity!, StringComparison.Ordinal) &&
            failure.Message.Contains(original.ExpectedParentIdentity!, StringComparison.Ordinal) && File.Exists(file));

        RemediationAction wrongFile = await DiagnosticFileActionAsync(file, RemediationActionType.AddProgramFirewallBlock,
            fileIdentity: original.ExpectedParentIdentity);
        failure = await CaptureScopeDiagnosticAsync(async () => _ = await PrepareScopeDiagnosticAsync(wrongFile));
        CheckScopeDiagnostic("prepare file identity is distinct from parent identity",
            DiagnosticIs(failure, "Scope.Diagnostic.Prepare.FileIdentity") && File.Exists(file));

        var fileAuthorization = await PrepareScopeDiagnosticAsync(original);
        File.Move(file, file + ".original");
        await File.WriteAllTextAsync(file, contents);
        failure = await CaptureScopeDiagnosticAsync(async () =>
        {
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(file, original.ExpectedParentIdentity);
            await using SecureFileLease source = SecureFileLease.Open(file);
            _ = await fileAuthorization.VerifyLockedAsync(original, source, parent, CancellationToken.None);
        });
        CheckScopeDiagnostic("same content replacement is still rejected at execution file identity",
            DiagnosticIs(failure, "Scope.Diagnostic.Execute.FileIdentity") &&
            await File.ReadAllTextAsync(file) == contents && await File.ReadAllTextAsync(file + ".original") == contents);

        string parentFixture = Path.Combine(fixture, "replace-parent");
        Directory.CreateDirectory(parentFixture);
        string parentFile = Path.Combine(parentFixture, "inert.txt");
        await File.WriteAllTextAsync(parentFile, contents);
        RemediationAction parentAction = await DiagnosticFileActionAsync(parentFile, RemediationActionType.AddProgramFirewallBlock);
        _ = await PrepareScopeDiagnosticAsync(parentAction);
        Directory.Move(parentFixture, parentFixture + ".original");
        Directory.CreateDirectory(parentFixture);
        await File.WriteAllTextAsync(parentFile, contents);
        failure = await CaptureScopeDiagnosticAsync(() =>
        {
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(parentFile, parentAction.ExpectedParentIdentity);
            return Task.CompletedTask;
        });
        CheckScopeDiagnostic("replaced direct parent is rejected before opening the file",
            DiagnosticIs(failure, "Scope.Diagnostic.Execute.ParentIdentity") && File.Exists(parentFile));

        RemediationAction hashAction = await DiagnosticFileActionAsync(file, RemediationActionType.AddProgramFirewallBlock);
        BrokerFileScopeAuthorization hashAuthorization = await PrepareScopeDiagnosticAsync(hashAction);
        await File.WriteAllTextAsync(file, contents + " Changed only by this test.");
        failure = await CaptureScopeDiagnosticAsync(async () =>
        {
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(file, hashAction.ExpectedParentIdentity);
            await using SecureFileLease source = SecureFileLease.Open(file);
            _ = await hashAuthorization.VerifyLockedAsync(hashAction, source, parent, CancellationToken.None);
        });
        CheckScopeDiagnostic("content drift preserves invalid-data type and identifies SHA-256",
            failure is InvalidDataException && DiagnosticId(failure) == "Scope.Diagnostic.Execute.ContentSha256" &&
            FileScopeSafety.CaptureIdentity(file) == hashAction.ExpectedFileIdentity);

        failure = await CaptureScopeDiagnosticAsync(() =>
        {
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(Path.Combine(fixture, "absent", "inert.txt"));
            return Task.CompletedTask;
        });
        CheckScopeDiagnostic("ancestor open failure preserves native error and operation",
            failure is Win32Exception { NativeErrorCode: not 0 } && DiagnosticId(failure) == "Scope.Diagnostic.Execute.ParentOpen");

        await ScopeDiagnosticSerializationAsync(fixture);
        using WindowsIdentity account = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(account).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Skip("scope diagnostic native metadata drift fixtures require elevation");
            return;
        }
        await ScopeDiagnosticStableAttributesAsync(fixture);
        await ScopeDiagnosticMetadataDriftAsync(fixture, contents);
        _scopeNativeMetadataVerified = true;
    }

    private static async Task<RemediationAction> DiagnosticFileActionAsync(string path, RemediationActionType type,
        string? fileIdentity = null, string? parentIdentity = null) => new()
        {
            Type = type,
            Target = path,
            DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.CreateFileActionAsync.01"),
            ExpectedSha256 = await Hashing.Sha256FileAsync(path),
            ExpectedFileIdentity = fileIdentity ?? FileScopeSafety.CaptureIdentity(path),
            ExpectedParentIdentity = parentIdentity ?? FileScopeSafety.CaptureIdentity(Path.GetDirectoryName(path)!, directory: true)
        };

    private static async Task<BrokerFileScopeAuthorization> PrepareScopeDiagnosticAsync(RemediationAction action)
    {
        RemediationPlan plan = new() { ExplicitFileTargetsRequested = true, Actions = [action] };
        BrokerFileScopeAuthorization authorization = await BrokerFileScopeAuthorization.PrepareAsync(plan,
            new RuleSet(), new SteamLayout(), CancellationToken.None);
        authorization.ConfirmOnce(plan);
        authorization.BeginExecution(plan);
        return authorization;
    }

    private static async Task<Exception?> CaptureScopeDiagnosticAsync(Func<Task> operation)
    {
        try { await operation(); return null; }
        catch (Exception ex) { return ex; }
    }

    private static string? DiagnosticId(Exception? error) => error is null ? null : MessageExceptions.Describe(error).Message?.MessageId;
    private static bool DiagnosticIs(Exception? error, string id) => error is UnauthorizedAccessException && DiagnosticId(error) == id;

    private static async Task ScopeDiagnosticSerializationAsync(string fixture)
    {
        BrokerFileMetadata expected = new("O:BAG:BAD:(A;;FA;;;BA)", 128,
            DateTimeOffset.Parse("2020-01-02T03:04:05Z"), DateTimeOffset.Parse("2021-02-03T04:05:06Z"));
        BrokerFileMetadata actual = expected with
        {
            SecurityDescriptor = "O:BAG:BAD:P(A;;FA;;;BA)",
            Attributes = 3,
            CreationTimeUtc = expected.CreationTimeUtc.AddSeconds(1),
            LastWriteTimeUtc = expected.LastWriteTimeUtc.AddSeconds(2)
        };
        MessageText metadata = BrokerScopeText.MetadataDifference(BrokerFileValidationStage.Execute, expected, actual);
        CheckScopeDiagnostic("four metadata fields fit exception limit without disclosing SDDL",
            metadata.Message?.Arguments.Count == 4 && metadata.Message.Arguments.All(argument => argument.OriginalText.Contains(" → ", StringComparison.Ordinal)) &&
            metadata.OriginalText.Length + nameof(UnauthorizedAccessException).Length + 2 < 700 &&
            !metadata.OriginalText.Contains(expected.SecurityDescriptor, StringComparison.Ordinal) &&
            !metadata.OriginalText.Contains(actual.SecurityDescriptor, StringComparison.Ordinal));

        MessageText ancestor = BrokerScopeText.IdentityDifference(BrokerFileValidationStage.Execute, "AncestorPath",
            @"C:\inert\" + new string('a', 5000), @"C:\inert\" + new string('b', 5000));
        CheckScopeDiagnostic("long ancestor paths retain bounded bilingual fingerprints",
            ancestor.Message is not null && ancestor.OriginalText.Length + nameof(UnauthorizedAccessException).Length + 2 < 700 &&
            ancestor.Message.Arguments.All(argument => argument.OriginalText.Contains("SHA-256:", StringComparison.Ordinal)));

        foreach ((string name, MessageText detail) in new[] { ("metadata", metadata), ("ancestor path", ancestor) })
            foreach (bool hasOccupancy in new[] { false, true })
            {
                RemediationAction action = new()
                {
                    Type = RemediationActionType.QuarantineFile,
                    Target = Path.Combine(fixture, "inert-" + name + ".txt"),
                    DisplayNameText = MessageText.Create("Backend.Core.RemediationPlanBuilder.CreateFileActionAsync.01")
                };
                RemediationPlan plan = new() { Actions = [action] };
                RemediationRunResult result = new() { PlanId = plan.PlanId };
                await BrokerActionSequencer.RunLocalizedAsync(plan, result, new Dictionary<Guid, MessageText>(),
                    (_, _) => Task.FromException<MessageText>(BrokerScopeText.Denied(detail)),
                    (_, outcome, _) => { outcome.VerificationStatus = RemediationVerificationStatus.ResidualDetected; return Task.CompletedTask; },
                    _ => Task.CompletedTask,
                    (_, outcome, _) =>
                    {
                        outcome.Occupancy = new()
                        {
                            Status = hasOccupancy ? FileOccupancyStatus.LocksReported : FileOccupancyStatus.NoLocksReported,
                            DiagnosticText = hasOccupancy ? "Inert occupancy fixture." : MessageText.Create("Backend.Core.FileOccupancy.Inspect.07"),
                            Processes = hasOccupancy ? [new() { ProcessId = 12345, ProcessName = "inert-fixture" }] : []
                        };
                        outcome.MessageText = FileOccupancy.AppendTo(outcome.MessageText, outcome.Occupancy);
                    });
                string json = JsonSerializer.Serialize(result, JsonFile.Options);
                await JsonFile.WriteNewAsync(Path.Combine(fixture, $"result-{name.Replace(' ', '-')}-{hasOccupancy}.json"), result);
                RemediationRunResult received = JsonSerializer.Deserialize<RemediationRunResult>(json, JsonFile.Options)!;
                CheckScopeDiagnostic(name + " survives real action-loop occupancy and JSON wrappers " + hasOccupancy,
                    received.Actions.Single().ExecutionStatus == RemediationExecutionStatus.Failed &&
                    received.Actions.Single().ResultMessage is not null && received.ErrorMessages?.Single() is not null &&
                    json.Contains(detail.Message!.MessageId, StringComparison.Ordinal));
                foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
                {
                    using IDisposable language = DisplayText.UseCulture(culture);
                    string rendered = received.Actions.Single().MessageText.Display;
                    string renderedError = received.DisplayErrors.Single();
                    string marker = culture.Equals(DisplayText.English) ? "pre-execution verification" : "执行前复验";
                    CheckScopeDiagnostic(name + " result and error render stage in " + culture.Name + " occupancy " + hasOccupancy,
                        rendered.Contains(marker, StringComparison.Ordinal) && renderedError.Contains(marker, StringComparison.Ordinal) &&
                        JsonSerializer.Serialize(received, JsonFile.Options) == json);
                }
            }
    }

    private static async Task ScopeDiagnosticStableAttributesAsync(string fixture)
    {
        FileAttributes[] attributes = [FileAttributes.Normal, FileAttributes.Archive, FileAttributes.ReadOnly,
            FileAttributes.ReadOnly | FileAttributes.Archive, FileAttributes.Hidden, FileAttributes.ReadOnly | FileAttributes.Hidden,
            FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive, FileAttributes.System,
            FileAttributes.NotContentIndexed, FileAttributes.Temporary];
        foreach (FileAttributes attribute in attributes)
        {
            string file = Path.Combine(fixture, "stable-" + (int)attribute + ".txt");
            await File.WriteAllTextAsync(file, "Inert metadata stability fixture. Never executed.");
            File.SetAttributes(file, attribute);
            try
            {
                RemediationAction action = await DiagnosticFileActionAsync(file, RemediationActionType.QuarantineFile);
                BrokerFileScopeAuthorization authorization = await PrepareScopeDiagnosticAsync(action);
                bool equal;
                using (BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(file, action.ExpectedParentIdentity))
                await using (SecureFileLease source = SecureFileLease.OpenWithSecurity(file))
                {
                    VerifiedBrokerFileTarget verified = await authorization.VerifyLockedAsync(action, source, parent, CancellationToken.None);
                    source.DeleteOnClose();
                    try { equal = BrokerFileMetadata.CaptureLocked(source.Handle) == verified.Metadata; }
                    finally { source.CancelDelete(); }
                }
                CheckScopeDiagnostic("ordinary and security handles plus delete cancellation remain stable " + attribute,
                    equal && File.Exists(file) && File.GetAttributes(file) == attribute &&
                    FileScopeSafety.CaptureIdentity(file) == action.ExpectedFileIdentity);
            }
            finally { if (File.Exists(file)) File.SetAttributes(file, FileAttributes.Normal); }
        }
    }

    private static async Task ScopeDiagnosticMetadataDriftAsync(string fixture, string contents)
    {
        for (int field = 0; field < 4; field++)
        {
            string file = Path.Combine(fixture, "before-execution-" + field + ".txt");
            string payload = file + ".quarantined";
            await File.WriteAllTextAsync(file, contents);
            RemediationAction action = await DiagnosticFileActionAsync(file, RemediationActionType.QuarantineFile);
            BrokerFileScopeAuthorization authorization = await PrepareScopeDiagnosticAsync(action);
            FileSecurity originalSecurity = new FileInfo(file).GetAccessControl();
            try
            {
                if (field == 0)
                {
                    FileSecurity changed = new();
                    changed.SetSecurityDescriptorBinaryForm(originalSecurity.GetSecurityDescriptorBinaryForm());
                    changed.SetAccessRuleProtection(true, preserveInheritance: true);
                    new FileInfo(file).SetAccessControl(changed);
                }
                else if (field == 1) File.SetAttributes(file, FileAttributes.Hidden);
                else if (field == 2) File.SetCreationTimeUtc(file, File.GetCreationTimeUtc(file).AddMinutes(-1));
                else File.SetLastWriteTimeUtc(file, File.GetLastWriteTimeUtc(file).AddMinutes(-1));
                bool persisted = false;
                Exception? error = await CaptureScopeDiagnosticAsync(async () =>
                    _ = await BrokerEngine.QuarantineExplicitFileAsync(action, authorization, payload,
                        (_, _) => { persisted = true; return Task.CompletedTask; }, _ => { }, CancellationToken.None));
                DisplayMessage? diagnostic = error is null ? null : MessageExceptions.Describe(error).Message;
                CheckScopeDiagnostic("execution metadata drift reports only changed field " + field,
                    DiagnosticIs(error, "Scope.Diagnostic.Execute.Metadata") && diagnostic?.Arguments.Count == 4 &&
                    diagnostic.Arguments.Select((argument, index) => index == field
                        ? argument.OriginalText.Contains(" → ", StringComparison.Ordinal) : argument.OriginalText == "=").All(value => value));
                CheckScopeDiagnostic("execution metadata drift retains source before persistence " + field,
                    !persisted && !File.Exists(payload) && await File.ReadAllTextAsync(file) == contents &&
                    FileScopeSafety.CaptureIdentity(file) == action.ExpectedFileIdentity);
            }
            finally
            {
                File.SetAttributes(file, FileAttributes.Normal);
                if (field == 0) new FileInfo(file).SetAccessControl(originalSecurity);
            }
        }
        foreach (bool changeAttributes in new[] { false, true })
        {
            string file = Path.Combine(fixture, "final-check-" + changeAttributes + ".txt");
            string payload = file + ".quarantined";
            await File.WriteAllTextAsync(file, contents);
            RemediationAction action = await DiagnosticFileActionAsync(file, RemediationActionType.QuarantineFile);
            BrokerFileScopeAuthorization authorization = await PrepareScopeDiagnosticAsync(action);
            QuarantineRecord? persisted = null;
            try
            {
                Exception? error = await CaptureScopeDiagnosticAsync(async () =>
                    _ = await BrokerEngine.QuarantineExplicitFileAsync(action, authorization, payload,
                        (record, _) =>
                        {
                            persisted = record;
                            if (changeAttributes) File.SetAttributes(file, FileAttributes.Hidden);
                            else File.SetLastWriteTimeUtc(file, File.GetLastWriteTimeUtc(file).AddMinutes(-1));
                            return Task.CompletedTask;
                        }, _ => { }, CancellationToken.None));
                DisplayMessage? diagnostic = error is null ? null : MessageExceptions.Describe(error).Message;
                CheckScopeDiagnostic("final metadata drift identifies post-disposition stage " + changeAttributes,
                    DiagnosticIs(error, "Scope.Diagnostic.FinalQuarantine.Metadata") &&
                    diagnostic?.Arguments[changeAttributes ? 1 : 3].OriginalText.Contains(" → ", StringComparison.Ordinal) == true);
                CheckScopeDiagnostic("final metadata drift cancels deletion and retains authenticated backup " + changeAttributes,
                    persisted is { MutationConfirmed: false, ExplicitFileAuthorization: true } &&
                    await File.ReadAllTextAsync(file) == contents && await File.ReadAllTextAsync(payload) == contents &&
                    FileScopeSafety.CaptureIdentity(file) == action.ExpectedFileIdentity);
            }
            finally { if (File.Exists(file)) File.SetAttributes(file, FileAttributes.Normal); }
        }
    }
}
