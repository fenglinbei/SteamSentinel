using SteamSentinel.Core.Reporting;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    internal static readonly MessageText DirectoryRollbackSafetyMessage =
        MessageText.Create("Backend.Broker.BrokerEngine.DirectoryRollbackSafetyMessage.01");
    private const int MaximumManifestBytes = 1024 * 1024;
    private readonly RuleSet _rules = RuleLoader.LoadEmbedded();
    private readonly SteamLayout _steamLayout = SteamLocator.Discover();
    private readonly IIncidentTrustStore _incidentTrustStore;
    private readonly IIncidentStateSecurity _incidentStateSecurity;
    private RemediationRunResult _result = null!;
    private QuarantineManifest _manifest = null!;
    private string _incidentRoot = string.Empty;
    private string _manifestPath = string.Empty;
    private bool _persistOwnManifest;
    private string _requestedBySid = string.Empty;
    private RemediationVerification _verification = null!;

    internal BrokerEngine() : this(new RegistryIncidentTrustStore(), new WindowsIncidentStateSecurity()) { }

    internal BrokerEngine(IIncidentTrustStore incidentTrustStore) :
        this(incidentTrustStore, new WindowsIncidentStateSecurity())
    { }

    internal BrokerEngine(IIncidentTrustStore incidentTrustStore, IIncidentStateSecurity incidentStateSecurity)
    {
        _incidentTrustStore = incidentTrustStore ?? throw new ArgumentNullException(nameof(incidentTrustStore));
        _incidentStateSecurity = incidentStateSecurity ?? throw new ArgumentNullException(nameof(incidentStateSecurity));
    }

    public Task<RemediationRunResult> ExecuteAsync(RemediationPlan plan, CancellationToken cancellationToken = default) =>
        BrokerExecutionBoundary.RunAsync(plan, () => ValidateBeforeExecution(plan),
            () => ExecuteValidatedAsync(plan, cancellationToken));

    internal void ValidateBeforeExecution(RemediationPlan plan)
    {
        // This entire phase must remain read-only. No incident directory, backup or action may be created here.
        ValidatePlan(plan);
        _requestedBySid = plan.RequestedBySid;
        foreach (RemediationAction action in plan.Actions) ValidateAction(action);
        ValidateConfigurationPlan(plan);
    }

    private async Task<RemediationRunResult> ExecuteValidatedAsync(RemediationPlan plan, CancellationToken cancellationToken)
    {
        _result = new RemediationRunResult { PlanId = plan.PlanId, PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan) };
        _contentProofs.Clear();
        _verification = new(new WindowsRemediationStateProbe(async (script, token) =>
        {
            ProcessResult output = await RunEncodedPowerShellAsync(script, null, token);
            return output.ExitCode == 0 && output.Output.Length <= 16_384 ? output.Output.Trim() : null;
        }, _result.IncidentId));
        _persistOwnManifest = plan.Actions[0].Type is not (RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (_persistOwnManifest)
        {
            _incidentRoot = Path.Combine(AppPaths.QuarantineRoot, _result.IncidentId.ToString("D"));
            _manifestPath = Path.Combine(_incidentRoot, "manifest.json");
            MachineStateSecurity.PrepareIncidentDirectory(_incidentRoot, plan.RequestedBySid);
            _manifest = new QuarantineManifest
            {
                IncidentId = _result.IncidentId,
                PlanId = plan.PlanId,
                TrustId = Guid.NewGuid(),
                RequestedBySid = plan.RequestedBySid,
                ActionOrder = plan.Actions.Select(a => a.ActionId).ToList()
            };
            _result.ManifestPath = _manifestPath;
            await InitializeManifestAsync(cancellationToken);
        }

        Dictionary<Guid, MessageText> preparationFailures = await PrepareConfigurationBackupsAsync(plan, cancellationToken);
        await BrokerActionSequencer.RunLocalizedAsync(plan, _result, preparationFailures,
            async (action, token) =>
            {
                ValidateAction(action);
                MessageText message = await ExecuteActionAsync(action, token);
                if (_persistOwnManifest)
                {
                    bool confirmedRecord = false;
                    foreach (QuarantineRecord record in _manifest.Records.Where(record => record.ActionId == action.ActionId))
                    {
                        if (record.MutationConfirmed) continue;
                        record.MutationConfirmed = true;
                        confirmedRecord = true;
                    }
                    if (confirmedRecord) await PersistManifestAsync(token);
                }
                return message;
            },
            (action, actionResult, token) => _verification.ObserveAsync(action, actionResult, 1, token),
            token => _persistOwnManifest ? PersistManifestAsync(token) : Task.CompletedTask,
            (action, actionResult, ex) =>
            {
                if (action.Type is RemediationActionType.QuarantineFile or RemediationActionType.QuarantineDirectory &&
                    ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
                {
                    actionResult.Occupancy = FileOccupancy.Inspect(action.Target, action.Type == RemediationActionType.QuarantineDirectory);
                    actionResult.MessageText += " " + FileOccupancy.DescribeText(actionResult.Occupancy);
                }
            }, cancellationToken);

        await _verification.CompleteAsync(plan, _result, cancellationToken);
        _result.CompletedAtUtc = DateTimeOffset.UtcNow;
        _result.Disposition = RemediationRunDisposition.Completed;
        _result.Success = _result.Errors.Count == 0 && _result.Actions.All(action => action.Success);
        if (_persistOwnManifest) await PersistManifestAsync(cancellationToken);
        return _result;
    }

    private void ValidatePlan(RemediationPlan plan)
    {
        if (plan.SchemaVersion != "1") throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.01"), sourceText => new InvalidDataException(sourceText));
        if (plan.PlanId == Guid.Empty) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.02"), sourceText => new InvalidDataException(sourceText));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (plan.CreatedAtUtc == default || plan.ExpiresAtUtc == default ||
            plan.CreatedAtUtc > now.AddMinutes(2) || plan.ExpiresAtUtc < now ||
            plan.ExpiresAtUtc <= plan.CreatedAtUtc ||
            plan.ExpiresAtUtc - plan.CreatedAtUtc > TimeSpan.FromHours(1))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.03"), sourceText => new InvalidDataException(sourceText));
        }
        if (plan.Actions is null || plan.Actions.Count is < 1 or > 64)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.04"), sourceText => new InvalidDataException(sourceText));
        if (string.IsNullOrWhiteSpace(plan.RequestedBy) || plan.RequestedBy.Length > 256 ||
            string.IsNullOrWhiteSpace(plan.RequestedBySid) || plan.RequestedBySid.Length > 184)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.05"), sourceText => new InvalidDataException(sourceText));
        SecurityIdentifier requester;
        try { requester = new SecurityIdentifier(plan.RequestedBySid); }
        catch (ArgumentException ex) { throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.06"), sourceText => new InvalidDataException(sourceText, ex)); }
        string currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        if (!requester.Value.Equals(currentSid, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.07"), sourceText => new UnauthorizedAccessException(sourceText));
        if (plan.Actions.Any(action => action is null || action.ActionId == Guid.Empty) ||
            plan.Actions.Select(action => action.ActionId).Distinct().Count() != plan.Actions.Count)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.08"), sourceText => new InvalidDataException(sourceText));
        bool hasIncidentLifecycleAction = plan.Actions.Any(action =>
            action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident);
        if (hasIncidentLifecycleAction && plan.Actions.Count != 1)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidatePlan.09"), sourceText => new InvalidDataException(sourceText));
        _ = RemediationDependencies.Build(plan.Actions);
    }

    private void ValidateAction(RemediationAction action)
    {
        if (string.IsNullOrWhiteSpace(action.Target) || action.Target.Length > 32_768 ||
            action.DisplayName is null || action.DisplayName.Length > 500)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.01"), sourceText => new InvalidDataException(sourceText));

        switch (action.Type)
        {
            case RemediationActionType.StopProcess:
                if (action.ProcessId is null or <= 4 || action.ProcessStartedAtUtc is null || !Path.IsPathFullyQualified(action.Target) ||
                    !Validation.IsHexSha256(action.ExpectedSha256) ||
                    IsWithin(action.Target, Environment.GetFolderPath(Environment.SpecialFolder.Windows)) || IsWithin(action.Target, AppContext.BaseDirectory) ||
                    !IsKnownImageHash(action.ExpectedSha256) && !HasDirectStrongBinding(action))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.02"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.QuarantineFile:
                ValidateQuarantinePath(action.Target, isDirectory: false, action.ExpectedSha256);
                break;
            case RemediationActionType.QuarantineDirectory:
                ValidateQuarantinePath(action.Target, isDirectory: true, action.ExpectedSha256);
                break;
            case RemediationActionType.RemoveRegistryValue:
                if (action.RegistryHive is not ("HKCU" or "HKLM") ||
                    action.RegistryKey is not (@"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce") ||
                    string.IsNullOrWhiteSpace(action.RegistryValueName) ||
                    action.ExpectedValueData is null ||
                    action.RegistryView is not ("Default" or "Registry32" or "Registry64") ||
                    (!_rules.KnownRunValueNames.Contains(action.RegistryValueName, StringComparer.OrdinalIgnoreCase) && !HasPersistenceBinding(action)))
                {
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.03"), sourceText => new UnauthorizedAccessException(sourceText));
                }
                break;
            case RemediationActionType.RemoveScheduledTask:
                string taskName = action.TaskName ?? action.Target;
                if (!Validation.TryNormalizeScheduledTaskName(taskName, out string normalizedTask) ||
                    !Validation.IsHexSha256(action.ExpectedSha256) ||
                    (!_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)) && !HasPersistenceBinding(action)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.04"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
            case RemediationActionType.RemoveDefenderExclusion:
                if (!IsKnownPath(action.Target))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.05"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
            case RemediationActionType.AddProgramFirewallBlock:
                if (!Path.IsPathFullyQualified(action.Target) || !Validation.IsHexSha256(action.ExpectedSha256))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.06"), sourceText => new InvalidDataException(sourceText));
                if (!IsAllowedFileTarget(action.Target, action.ExpectedSha256))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.07"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
            case RemediationActionType.BlockKnownDomains:
                if (action.Domains.Count == 0 || action.Domains.Any(domain =>
                        !_rules.KnownDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.08"), sourceText => new UnauthorizedAccessException(sourceText));
                break;
            case RemediationActionType.RestoreSecurityControls:
                if (action.Target != "Windows Security") throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.09"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.StopHostProcess:
            case RemediationActionType.DisableService:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
            case RemediationActionType.DisableRelatedFirewallRule:
                ValidateBoundAction(action);
                break;
            case RemediationActionType.RemoveBoundCertificate:
            case RemediationActionType.RestoreBoundProxyConfiguration:
                ValidateConfigurationAction(action);
                break;
            case RemediationActionType.RollbackIncident:
            case RemediationActionType.DeleteIncident:
                if (!Guid.TryParse(action.IncidentId ?? action.Target, out _)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.10"), sourceText => new InvalidDataException(sourceText));
                break;
            default:
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateAction.11", (action.Type)), sourceText => new NotSupportedException(sourceText));
        }
    }

    private async Task<MessageText> ExecuteActionAsync(RemediationAction action, CancellationToken cancellationToken) => action.Type switch
    {
        RemediationActionType.StopProcess => await StopProcessAsync(action, cancellationToken),
        RemediationActionType.QuarantineFile => await QuarantineFileAsync(action, cancellationToken),
        RemediationActionType.QuarantineDirectory => await QuarantineDirectoryAsync(action, cancellationToken),
        RemediationActionType.RemoveRegistryValue => await RemoveRegistryValueAsync(action, cancellationToken),
        RemediationActionType.RemoveScheduledTask => await RemoveScheduledTaskAsync(action, cancellationToken),
        RemediationActionType.RemoveDefenderExclusion => await ChangeDefenderExclusionAsync(action, add: false, cancellationToken),
        RemediationActionType.AddProgramFirewallBlock => await AddFirewallRuleAsync(action, cancellationToken),
        RemediationActionType.BlockKnownDomains => await BlockDomainsAsync(action, cancellationToken),
        RemediationActionType.RestoreSecurityControls => await RestoreSecurityControlsAsync(cancellationToken),
        RemediationActionType.StopHostProcess => await StopHostAsync(action, cancellationToken),
        RemediationActionType.DisableService => await DisableServiceAsync(action, cancellationToken),
        RemediationActionType.RemoveRelatedDefenderExclusion => await ChangeRelatedExclusionAsync(action, false, cancellationToken),
        RemediationActionType.DisableRelatedFirewallRule => await ChangeRelatedFirewallAsync(action, false, cancellationToken),
        RemediationActionType.RemoveBoundCertificate or RemediationActionType.RestoreBoundProxyConfiguration =>
            await ExecuteConfigurationActionAsync(action, cancellationToken),
        RemediationActionType.RollbackIncident => await RollbackIncidentAsync(action, cancellationToken),
        RemediationActionType.DeleteIncident => await DeleteIncidentAsync(action, cancellationToken),
        _ => throw new NotSupportedException()
    };

    private async Task<MessageText> StopProcessAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        using Process process = Process.GetProcessById(action.ProcessId!.Value);
        if (action.ProcessStartedAtUtc is { } expectedStart && process.StartTime.ToUniversalTime() != expectedStart.UtcDateTime)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.StopProcessAsync.01"), sourceText => new InvalidOperationException(sourceText));
        string? image = process.MainModule?.FileName;
        if (image is null || !PathsEquivalent(image, action.Target))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.StopProcessAsync.02"), sourceText => new InvalidOperationException(sourceText));
        await using SecureFileLease lease = SecureFileLease.Open(image);
        string currentHash = await lease.ComputeSha256Async(cancellationToken);
        if (!currentHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.StopProcessAsync.03"), sourceText => new InvalidOperationException(sourceText));
        await VerifyDirectProcessContentAsync(action, lease, cancellationToken);
        if (!PathsEquivalent(process.MainModule?.FileName ?? string.Empty, lease.FinalPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.StopProcessAsync.04"), sourceText => new InvalidOperationException(sourceText));
        process.Kill(entireProcessTree: false);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(timeout.Token);
        return MessageText.Create("Backend.Broker.BrokerEngine.StopProcessAsync.05", (action.ProcessId));
    }

    private async Task<MessageText> QuarantineFileAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string source = Path.GetFullPath(action.Target);
        if (!File.Exists(source)) return MessageText.Create("Backend.Broker.BrokerEngine.QuarantineFileAsync.01");
        await using SecureFileLease lease = SecureFileLease.Open(source);
        if (!IsAllowedFileTarget(lease.FinalPath, action.ExpectedSha256))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.QuarantineFileAsync.02"), sourceText => new UnauthorizedAccessException(sourceText));
        string currentHash = await lease.ComputeSha256Async(cancellationToken);
        if (!currentHash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.QuarantineFileAsync.03"), sourceText => new InvalidOperationException(sourceText));

        string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
        MachineStateSecurity.PreparePayloadDirectory(itemRoot);
        string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(source)) + ".quarantined");
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = lease.FinalPath,
            QuarantinedPath = destination,
            Sha256 = currentHash
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);
        await lease.CopyToAsync(destination, currentHash, cancellationToken);
        MachineStateSecurity.ProtectPayloadFile(destination);
        lease.DeleteOnClose();
        return MessageText.Create("Backend.Broker.BrokerEngine.QuarantineFileAsync.04", (destination));
    }

    private async Task<MessageText> QuarantineDirectoryAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(action.Target));
        if (!Directory.Exists(source)) return MessageText.Create("Backend.Broker.BrokerEngine.QuarantineDirectoryAsync.01");
        EnsureTreeHasNoReparsePoints(source);
        string currentFingerprint = await DirectoryFingerprint.ComputeAsync(source, cancellationToken);
        if (!currentFingerprint.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.QuarantineDirectoryAsync.02"), sourceText => new InvalidOperationException(sourceText));
        string itemRoot = Path.Combine(_incidentRoot, "items", action.ActionId.ToString("N"));
        MachineStateSecurity.PreparePayloadDirectory(itemRoot);
        string destination = Path.Combine(itemRoot, SafeName(Path.GetFileName(source)) + ".quarantined");
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = source,
            QuarantinedPath = destination,
            Sha256 = currentFingerprint
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);

        // Always copy into a newly ACL-protected tree. A same-volume rename would preserve
        // attacker-controlled source ACLs and make the elevated rollback input writable.
        await CopyDirectoryVerifiedAsync(source, destination, currentFingerprint, cancellationToken);
        MachineStateSecurity.EnsureProtectedSubtree(destination);
        await DeleteDirectorySnapshotAsync(source, currentFingerprint, cancellationToken);
        return MessageText.Create("Backend.Broker.BrokerEngine.QuarantineDirectoryAsync.03", (destination));
    }

    private async Task<MessageText> RemoveRegistryValueAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        RegistryView view = Enum.Parse<RegistryView>(action.RegistryView!, ignoreCase: false);
        RegistryHive hive = action.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey? key = baseKey.OpenSubKey(action.RegistryKey!, writable: true);
        if (key is null) return MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.01");
        object? value = key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null) return MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.02");
        if (!string.Equals(value.ToString(), action.ExpectedValueData, StringComparison.Ordinal))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.03"), sourceText => new InvalidOperationException(sourceText));
        await using SecureFileLease? bound = HasPersistenceBinding(action)
            ? await OpenBoundLeaseAsync(action, value.ToString(), cancellationToken) : null;
        RegistryValueKind kind = key.GetValueKind(action.RegistryValueName!);
        if (kind is not (RegistryValueKind.String or RegistryValueKind.ExpandString))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.04"), sourceText => new InvalidDataException(sourceText));
        QuarantineRecord record = new()
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            RegistryHive = action.RegistryHive,
            RegistryView = action.RegistryView,
            RegistryKey = action.RegistryKey,
            RegistryValueName = action.RegistryValueName,
            RegistryValueData = value.ToString(),
            RegistryValueKind = (int)kind,
            MutationConfirmed = false,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = _contentProofs.GetValueOrDefault(action.ActionId)
        };
        _manifest.Records.Add(record);
        await PersistManifestAsync(cancellationToken);
        object? latest = key.GetValue(action.RegistryValueName!, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (!string.Equals(latest?.ToString(), action.ExpectedValueData, StringComparison.Ordinal) || key.GetValueKind(action.RegistryValueName!) != kind)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.05"), sourceText => new InvalidOperationException(sourceText));
        key.DeleteValue(action.RegistryValueName!, throwOnMissingValue: false);
        record.MutationConfirmed = true;
        await PersistManifestAsync(cancellationToken);
        return MessageText.Create("Backend.Broker.BrokerEngine.RemoveRegistryValueAsync.06", (action.RegistryHive), (action.RegistryKey), (action.RegistryValueName));
    }

    private async Task<MessageText> RemoveScheduledTaskAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Validation.TryNormalizeScheduledTaskName(action.TaskName ?? action.Target, out string taskName);
        string relative = taskName.TrimStart('\\').Replace('\\', Path.DirectorySeparatorChar);
        string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        string taskFile = Path.GetFullPath(Path.Combine(tasksRoot, relative));
        if (!IsWithin(taskFile, tasksRoot) || Validation.ContainsReparsePoint(Path.GetDirectoryName(taskFile)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveScheduledTaskAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
        string? backup = null;
        await using SecureFileLease? bound = HasPersistenceBinding(action) ? await OpenBoundLeaseAsync(action, action.ConfigurationSnapshot, cancellationToken) : null;
        if (!File.Exists(taskFile)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveScheduledTaskAsync.02"), sourceText => new InvalidOperationException(sourceText));
        if (File.Exists(taskFile))
        {
            backup = Path.Combine(_incidentRoot, "tasks", action.ActionId.ToString("N") + ".xml");
            MachineStateSecurity.PreparePayloadDirectory(Path.GetDirectoryName(backup)!);
            await using SecureFileLease taskLease = SecureFileLease.Open(taskFile);
            string taskHash = await taskLease.ComputeSha256Async(cancellationToken);
            RequireTaskSnapshotHash(taskHash, action.ExpectedSha256);
            await taskLease.CopyToAsync(backup, taskHash, cancellationToken);
            MachineStateSecurity.ProtectPayloadFile(backup);
            if (HasPersistenceBinding(action))
            {
                string xml = await File.ReadAllTextAsync(backup, cancellationToken);
                if (!CommandTargetsAreBound(action, TaskCommands(xml))) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveScheduledTaskAsync.03"), sourceText => new InvalidOperationException(sourceText));
            }
        }
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = taskName,
            QuarantinedPath = backup,
            TaskName = taskName,
            Sha256 = action.ExpectedSha256,
            MutationConfirmed = false,
            RelatedFilePath = action.RelatedFilePath,
            RelatedFileSha256 = action.RelatedFileSha256,
            VerifiedContentRuleId = _contentProofs.GetValueOrDefault(action.ActionId)
        });
        await PersistManifestAsync(cancellationToken);
        // Scheduler deletion cannot share our deny-delete lease. Recheck after all awaited backup work,
        // then release immediately before invoking the fixed, exact-name Scheduler operation.
        await using (SecureFileLease finalTask = SecureFileLease.Open(taskFile))
            RequireTaskSnapshotHash(await finalTask.ComputeSha256Async(cancellationToken), action.ExpectedSha256);
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            ["/Delete", "/TN", taskName, "/F"], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        _manifest.Records.Last(record => record.ActionId == action.ActionId).MutationConfirmed = true;
        await PersistManifestAsync(cancellationToken);
        return MessageText.Create("Backend.Broker.BrokerEngine.RemoveScheduledTaskAsync.04");
    }

    private async Task<MessageText> ChangeDefenderExclusionAsync(RemediationAction action, bool add, CancellationToken cancellationToken)
    {
        string path = action.Target;
        string operation = add ? "Add-MpPreference" : "Remove-MpPreference";
        string script = "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:STEAMSENTINEL_PATH_B64));" +
                        operation + " -ExclusionPath $p -ErrorAction Stop";
        if (!add)
        {
            _manifest.Records.Add(new QuarantineRecord
            {
                ActionId = action.ActionId,
                Type = action.Type,
                OriginalTarget = path,
                DefenderExclusionPath = path
            });
            await PersistManifestAsync(cancellationToken);
        }
        ProcessResult result = await RunEncodedPowerShellAsync(script,
            new Dictionary<string, string> { ["STEAMSENTINEL_PATH_B64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(path)) },
            cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
        return add ? MessageText.Create("Backend.Broker.BrokerEngine.ChangeDefenderExclusionAsync.01") : MessageText.Create("Backend.Broker.BrokerEngine.ChangeDefenderExclusionAsync.02");
    }

    private async Task<MessageText> AddFirewallRuleAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        if (File.Exists(action.Target))
        {
            if (Validation.ContainsReparsePoint(action.Target))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.AddFirewallRuleAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
            string hash = await Hashing.Sha256FileExclusiveAsync(action.Target, cancellationToken);
            if (!hash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.AddFirewallRuleAsync.02"), sourceText => new InvalidOperationException(sourceText));
        }
        else if (!_rules.KnownHashes.Any(rule => rule.Malware && rule.Sha256.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase)))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.AddFirewallRuleAsync.03"), sourceText => new FileNotFoundException(sourceText, action.Target));
        }

        string name = $"SteamSentinel-{_result.IncidentId:N}-{action.ActionId:N}";
        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = action.Target,
            FirewallRuleName = name,
            Sha256 = action.ExpectedSha256
        });
        await PersistManifestAsync(cancellationToken);
        string netsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        ProcessResult command = await RunProcessAsync(netsh,
            ["advfirewall", "firewall", "add", "rule", $"name={name}", "dir=out", "action=block", "enable=yes", "profile=any", $"program={action.Target}"],
            cancellationToken);
        if (command.ExitCode != 0) throw new InvalidOperationException(command.Error);
        return MessageText.Create("Backend.Broker.BrokerEngine.AddFirewallRuleAsync.04", (name));
    }

    private async Task<MessageText> BlockDomainsAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        string original = File.Exists(hosts) ? await File.ReadAllTextAsync(hosts, cancellationToken) : string.Empty;
        string marker = _result.IncidentId.ToString("N");
        if (original.Contains($"# SteamSentinel BEGIN {marker}", StringComparison.Ordinal)) return MessageText.Create("Backend.Broker.BrokerEngine.BlockDomainsAsync.01");

        List<string> domains = action.Domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        StringBuilder addition = new();
        if (original.Length > 0 && !original.EndsWith('\n')) addition.AppendLine();
        addition.AppendLine($"# SteamSentinel BEGIN {marker}");
        foreach (string domain in domains)
        {
            addition.AppendLine($"0.0.0.0 {domain}");
            addition.AppendLine($":: {domain}");
        }
        addition.AppendLine($"# SteamSentinel END {marker}");

        _manifest.Records.Add(new QuarantineRecord
        {
            ActionId = action.ActionId,
            Type = action.Type,
            OriginalTarget = hosts,
            HostsDomains = domains
        });
        await PersistManifestAsync(cancellationToken);
        await File.AppendAllTextAsync(hosts, addition.ToString(), new UTF8Encoding(false), cancellationToken);
        return MessageText.Create("Backend.Broker.BrokerEngine.BlockDomainsAsync.02", (domains.Count));
    }

    private static async Task<MessageText> RestoreSecurityControlsAsync(CancellationToken cancellationToken)
    {
        const string script = "$problems=[Collections.Generic.List[string]]::new();$mayChange=$false;" +
            "try{$m=Get-MpComputerStatus -ErrorAction Stop;$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop|" +
            "Where-Object {$_.displayName -notmatch '^(Microsoft|Windows) Defender'});" +
            "$mayChange=($m.AMRunningMode -eq 'Normal' -and $av.Count -eq 0);" +
            "if(-not $mayChange){$problems.Add('Defender mode/third-party antivirus requires manual review, no Defender changes requested')}}catch{$problems.Add('Cannot confirm antivirus ownership: '+$_.Exception.Message)};" +
            "if($mayChange){try{Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop}catch{$problems.Add('Realtime: '+$_.Exception.Message)};" +
            "try{Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop}catch{$problems.Add('Behavior: '+$_.Exception.Message)}};" +
            "try{Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop}catch{$problems.Add('Firewall: '+$_.Exception.Message)};" +
            "if($problems.Count -gt 0){throw ($problems -join ', ')}";
        ProcessResult result = await RunEncodedPowerShellAsync(script, null, cancellationToken);
        if (result.ExitCode != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreSecurityControlsAsync.01") + result.Error, sourceText => new InvalidOperationException(sourceText));
        return MessageText.Create("Backend.Broker.BrokerEngine.RestoreSecurityControlsAsync.02");
    }

    private async Task<MessageText> RollbackIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        string manifestPath = Path.Combine(incidentRoot, "manifest.json");
        QuarantineManifest manifest = await LoadTrustedManifestAsync(incidentId, incidentRoot, manifestPath, cancellationToken);
        SetConfigurationRollbackContext(manifest, manifestPath);
        foreach (QuarantineRecord record in manifest.Records)
            ValidateQuarantineRecord(record, incidentRoot, incidentId);
        foreach (QuarantineRecord record in manifest.Records)
            await VerifyRecordedContentAsync(record, manifest, cancellationToken);

        foreach (QuarantineRecord record in RemediationDependencies.RollbackOrder(manifest))
        {
            if (record.RolledBack) continue;
            bool configurationRecord = record.Type is RemediationActionType.RemoveBoundCertificate or RemediationActionType.RestoreBoundProxyConfiguration;
            if (configurationRecord && !record.ConfigurationMutationAttempted)
            {
                record.RolledBack = true; // Only a prepared backup exists; no configuration setter was attempted.
                await PersistTrustedManifestAsync(manifestPath, manifest, cancellationToken);
                continue;
            }
            if (!record.MutationConfirmed && !configurationRecord) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RollbackIncidentAsync.01"), sourceText => new InvalidOperationException(sourceText));
            switch (record.Type)
            {
                case RemediationActionType.QuarantineFile:
                    await RestoreFileAsync(record, cancellationToken);
                    break;
                case RemediationActionType.QuarantineDirectory:
                    await RestoreDirectoryAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveRegistryValue:
                    RestoreRegistryValue(record);
                    break;
                case RemediationActionType.RemoveScheduledTask:
                    await RestoreScheduledTaskAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveDefenderExclusion:
                    await ChangeDefenderExclusionAsync(new RemediationAction
                    {
                        Type = RemediationActionType.RemoveDefenderExclusion,
                        Target = record.DefenderExclusionPath ?? record.OriginalTarget
                    }, add: true, cancellationToken);
                    break;
                case RemediationActionType.AddProgramFirewallBlock:
                    await RemoveFirewallRuleAsync(record.FirewallRuleName, cancellationToken);
                    break;
                case RemediationActionType.BlockKnownDomains:
                    await RemoveHostsMarkerAsync(incidentId, record.OriginalTarget, cancellationToken);
                    break;
                case RemediationActionType.DisableService:
                    await RestoreServiceAsync(record, cancellationToken);
                    break;
                case RemediationActionType.RemoveRelatedDefenderExclusion:
                    await ChangeRelatedExclusionAsync(FromRecord(record), true, cancellationToken);
                    break;
                case RemediationActionType.DisableRelatedFirewallRule:
                    await ChangeRelatedFirewallAsync(FromRecord(record), true, cancellationToken);
                    break;
                case RemediationActionType.RemoveBoundCertificate:
                case RemediationActionType.RestoreBoundProxyConfiguration:
                    await RestoreConfigurationAsync(record, incidentRoot, cancellationToken);
                    break;
            }
            record.RolledBack = true;
            await PersistTrustedManifestAsync(manifestPath, manifest, cancellationToken);
        }
        return MessageText.Create("Backend.Broker.BrokerEngine.RollbackIncidentAsync.02", (incidentId));
    }

    private async Task<MessageText> DeleteIncidentAsync(RemediationAction action, CancellationToken cancellationToken)
    {
        Guid incidentId = Guid.Parse(action.IncidentId ?? action.Target);
        string incidentRoot = GetIncidentRoot(incidentId);
        if (!Directory.Exists(incidentRoot)) return MessageText.Create("Backend.Broker.BrokerEngine.DeleteIncidentAsync.01");
        string manifestPath = Path.Combine(incidentRoot, "manifest.json");
        QuarantineManifest manifestData = await LoadTrustedManifestAsync(
            incidentId, incidentRoot, manifestPath, cancellationToken);
        EnsureIncidentDeletionAllowed(manifestData);
        DeleteDirectoryContentsExact(incidentRoot);
        Directory.Delete(incidentRoot, recursive: false);
        _incidentTrustStore.Delete(incidentId);
        return MessageText.Create("Backend.Broker.BrokerEngine.DeleteIncidentAsync.02", (incidentId));
    }

    internal static void EnsureIncidentDeletionAllowed(QuarantineManifest manifest)
    {
        if (manifest.Records.Any(record => !record.RolledBack))
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.EnsureIncidentDeletionAllowed.01") +
                MessageText.Create("Backend.Broker.BrokerEngine.EnsureIncidentDeletionAllowed.02"), sourceText => new InvalidOperationException(
sourceText));
        }
    }

    private async Task RestoreFileAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreFileAsync.01"), sourceText => new FileNotFoundException(sourceText, record.QuarantinedPath));
        if (File.Exists(record.OriginalTarget) || Directory.Exists(record.OriginalTarget))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreFileAsync.02", (record.OriginalTarget)), sourceText => new IOException(sourceText));
        if (!IsAllowedFileTarget(record.OriginalTarget, record.Sha256) ||
            Validation.ContainsReparsePoint(Path.GetDirectoryName(record.OriginalTarget)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreFileAsync.03"), sourceText => new UnauthorizedAccessException(sourceText));
        if (!Directory.Exists(Path.GetDirectoryName(record.OriginalTarget)!))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreFileAsync.04"), sourceText => new DirectoryNotFoundException(sourceText));
        await using SecureFileLease lease = SecureFileLease.Open(record.QuarantinedPath);
        string hash = await lease.ComputeSha256Async(cancellationToken);
        if (!hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreFileAsync.05"), sourceText => new InvalidDataException(sourceText));
        await lease.CopyToAsync(record.OriginalTarget, hash, cancellationToken);
        lease.DeleteOnClose();
    }

    private static Task RestoreDirectoryAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !Directory.Exists(record.QuarantinedPath))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreDirectoryAsync.01"), sourceText => new DirectoryNotFoundException(sourceText));
        cancellationToken.ThrowIfCancellationRequested();
        throw SteamSentinel.Core.Reporting.MessageExceptions.Create(DirectoryRollbackSafetyMessage, sourceText => new InvalidOperationException(sourceText));
    }

    private static void RestoreRegistryValue(QuarantineRecord record)
    {
        RegistryView view = Enum.Parse<RegistryView>(record.RegistryView!, ignoreCase: false);
        RegistryHive hive = record.RegistryHive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
        using RegistryKey key = baseKey.CreateSubKey(record.RegistryKey!, writable: true);
        if (key.GetValue(record.RegistryValueName!) is not null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreRegistryValue.01"), sourceText => new IOException(sourceText));
        key.SetValue(record.RegistryValueName!, record.RegistryValueData ?? string.Empty,
            (RegistryValueKind)(record.RegistryValueKind ?? (int)RegistryValueKind.String));
    }

    private static async Task RestoreScheduledTaskAsync(QuarantineRecord record, CancellationToken cancellationToken)
    {
        if (record.QuarantinedPath is null || !File.Exists(record.QuarantinedPath) || record.TaskName is null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreScheduledTaskAsync.01"), sourceText => new FileNotFoundException(sourceText, record.QuarantinedPath));
        if (!Validation.TryNormalizeScheduledTaskName(record.TaskName, out string normalizedTask))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreScheduledTaskAsync.02"), sourceText => new InvalidDataException(sourceText));
        string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        string taskFile = Path.Combine(tasksRoot, normalizedTask.TrimStart('\\').Replace('\\', Path.DirectorySeparatorChar));
        if (File.Exists(taskFile)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreScheduledTaskAsync.03"), sourceText => new IOException(sourceText));
        string backupHash = await Hashing.Sha256FileExclusiveAsync(record.QuarantinedPath, cancellationToken);
        if (!backupHash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RestoreScheduledTaskAsync.04"), sourceText => new InvalidDataException(sourceText));
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            ["/Create", "/TN", normalizedTask, "/XML", record.QuarantinedPath], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
    }

    private static async Task RemoveFirewallRuleAsync(string? name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        ProcessResult result = await RunProcessAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe"),
            ["advfirewall", "firewall", "delete", "rule", $"name={name}"], cancellationToken);
        if (result.ExitCode != 0) throw new InvalidOperationException(result.Error);
    }

    private static async Task RemoveHostsMarkerAsync(Guid incidentId, string hosts, CancellationToken cancellationToken)
    {
        if (!File.Exists(hosts)) return;
        string begin = $"# SteamSentinel BEGIN {incidentId:N}";
        string end = $"# SteamSentinel END {incidentId:N}";
        string[] lines = await File.ReadAllLinesAsync(hosts, cancellationToken);
        List<string> kept = [];
        bool inside = false;
        foreach (string line in lines)
        {
            if (line.Trim().Equals(begin, StringComparison.Ordinal)) { inside = true; continue; }
            if (inside && line.Trim().Equals(end, StringComparison.Ordinal)) { inside = false; continue; }
            if (!inside) kept.Add(line);
        }
        if (inside) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RemoveHostsMarkerAsync.01"), sourceText => new InvalidDataException(sourceText));
        await File.WriteAllLinesAsync(hosts, kept, new UTF8Encoding(false), cancellationToken);
    }

    private void ValidateQuarantineRecord(QuarantineRecord record, string incidentRoot, Guid incidentId)
    {
        if (record.OriginalTarget.Length is 0 or > 32_768)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.01"), sourceText => new InvalidDataException(sourceText));
        if (record.QuarantinedPath is { } quarantined)
        {
            if (!IsWithin(quarantined, incidentRoot))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.02"), sourceText => new UnauthorizedAccessException(sourceText));
            string existing = File.Exists(quarantined) || Directory.Exists(quarantined)
                ? quarantined
                : Path.GetDirectoryName(quarantined)!;
            if (Validation.ContainsReparsePoint(existing))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.03"), sourceText => new UnauthorizedAccessException(sourceText));
        }

        switch (record.Type)
        {
            case RemediationActionType.QuarantineFile:
                if (!Validation.IsHexSha256(record.Sha256) || !IsAllowedFileTarget(record.OriginalTarget, record.Sha256))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.04"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.QuarantineDirectory:
                if (!Validation.IsHexSha256(record.Sha256) || !IsAllowedDirectoryTarget(record.OriginalTarget))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.05"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.RemoveRegistryValue:
                if (record.RegistryHive is not ("HKCU" or "HKLM") ||
                    record.RegistryView is not ("Default" or "Registry32" or "Registry64") ||
                    record.RegistryKey is not (@"Software\Microsoft\Windows\CurrentVersion\Run" or @"Software\Microsoft\Windows\CurrentVersion\RunOnce") ||
                    string.IsNullOrWhiteSpace(record.RegistryValueName) ||
                    record.RegistryValueKind is not ((int)RegistryValueKind.String or (int)RegistryValueKind.ExpandString) ||
                    (!_rules.KnownRunValueNames.Contains(record.RegistryValueName, StringComparer.OrdinalIgnoreCase) && !HasKnownBinding(FromRecord(record)) && !HasHeuristicRecord(record)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.06"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.RemoveScheduledTask:
                if (!Validation.IsHexSha256(record.Sha256) ||
                    !Validation.TryNormalizeScheduledTaskName(record.TaskName, out string normalizedTask) ||
                    (!_rules.KnownTaskNames.Any(known =>
                        Validation.TryNormalizeScheduledTaskName(known, out string normalizedKnown) &&
                        normalizedTask.Equals(normalizedKnown, StringComparison.OrdinalIgnoreCase)) && !HasKnownBinding(FromRecord(record)) && !HasHeuristicRecord(record)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.07"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.RemoveDefenderExclusion:
                if (!IsKnownPath(record.DefenderExclusionPath ?? record.OriginalTarget))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.08"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.AddProgramFirewallBlock:
                if (record.FirewallRuleName is null ||
                    !record.FirewallRuleName.StartsWith($"SteamSentinel-{incidentId:N}-", StringComparison.Ordinal))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.09"), sourceText => new InvalidDataException(sourceText));
                break;
            case RemediationActionType.DisableService:
            case RemediationActionType.RemoveRelatedDefenderExclusion:
            case RemediationActionType.DisableRelatedFirewallRule:
                ValidateBoundAction(FromRecord(record));
                break;
            case RemediationActionType.RemoveBoundCertificate:
            case RemediationActionType.RestoreBoundProxyConfiguration:
                ValidateConfigurationRecord(record, incidentRoot);
                break;
            case RemediationActionType.BlockKnownDomains:
                string expectedHosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                if (!PathsEquivalent(record.OriginalTarget, expectedHosts) ||
                    record.HostsDomains.Any(domain => !_rules.KnownDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.10"), sourceText => new InvalidDataException(sourceText));
                break;
            default:
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantineRecord.11"), sourceText => new InvalidDataException(sourceText));
        }
    }

    private void ValidateQuarantinePath(string path, bool isDirectory, string? expectedHash)
    {
        if (!Validation.IsSafeExactTarget(path) || Validation.ContainsReparsePoint(path))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantinePath.01"), sourceText => new UnauthorizedAccessException(sourceText));
        if (isDirectory)
        {
            if (!Directory.Exists(path) || !Validation.IsHexSha256(expectedHash) || !IsAllowedDirectoryTarget(path))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantinePath.02"), sourceText => new UnauthorizedAccessException(sourceText));
        }
        else
        {
            if (!File.Exists(path) || !Validation.IsHexSha256(expectedHash) || !IsAllowedFileTarget(path, expectedHash))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantinePath.03"), sourceText => new UnauthorizedAccessException(sourceText));
        }
    }

    private bool IsAllowedDirectoryTarget(string path)
    {
        if (IsWithin(path, AppPaths.UserStateRoot) || IsWithin(path, AppPaths.MachineStateRoot) ||
            IsWithin(path, AppContext.BaseDirectory) ||
            IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return false;
        return IsKnownPath(path) || IsWithin(path, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ||
               _steamLayout.WorkshopRoots.Any(root => IsWithin(path, root));
    }

    private bool IsAllowedFileTarget(string path, string? hash) =>
        FileRemediationScope.IsAllowed(path, hash, _rules, _steamLayout);

    private bool IsKnownPath(string path) => _rules.KnownPathTemplates.Any(template =>
        PathsEquivalent(path, Environment.ExpandEnvironmentVariables(template)) ||
        IsWithin(path, Environment.ExpandEnvironmentVariables(template)));

    private static bool IsWithin(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            string fullCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
                   fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool PathsEquivalent(string left, string right)
    {
        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(left))
                .Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static async Task CopyDirectoryVerifiedAsync(
        string source,
        string destination,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        DirectoryFingerprintSnapshot snapshot = await DirectoryFingerprint.CaptureAsync(source, cancellationToken);
        if (!snapshot.Sha256.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.CopyDirectoryVerifiedAsync.01"), sourceText => new InvalidOperationException(sourceText));
        if (File.Exists(destination) || Directory.Exists(destination))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.CopyDirectoryVerifiedAsync.02"), sourceText => new IOException(sourceText));

        MachineStateSecurity.PreparePayloadDirectory(destination);
        bool completed = false;
        try
        {
            foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => entry.IsDirectory))
            {
                string targetDirectory = ResolveSnapshotPath(destination, entry.RelativePath);
                MachineStateSecurity.PreparePayloadDirectory(targetDirectory);
            }
            foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => !entry.IsDirectory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string sourceFile = ResolveSnapshotPath(source, entry.RelativePath);
                string targetFile = ResolveSnapshotPath(destination, entry.RelativePath);
                await using SecureFileLease lease = SecureFileLease.Open(sourceFile);
                if (!IsWithin(lease.FinalPath, source))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.CopyDirectoryVerifiedAsync.03"), sourceText => new UnauthorizedAccessException(sourceText));
                string sourceHash = await lease.ComputeSha256Async(cancellationToken);
                if (!sourceHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.CopyDirectoryVerifiedAsync.04", (entry.RelativePath)), sourceText => new InvalidOperationException(sourceText));
                await lease.CopyToAsync(targetFile, sourceHash, cancellationToken);
                MachineStateSecurity.ProtectPayloadFile(targetFile);
            }

            string sourceAfter = await DirectoryFingerprint.ComputeAsync(source, cancellationToken);
            string destinationAfter = await DirectoryFingerprint.ComputeAsync(destination, cancellationToken);
            if (!sourceAfter.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase) ||
                !destinationAfter.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.CopyDirectoryVerifiedAsync.05"), sourceText => new IOException(sourceText));
            completed = true;
        }
        finally
        {
            if (!completed && Directory.Exists(destination) && !Validation.ContainsReparsePoint(destination))
            {
                try
                {
                    DeleteDirectoryContentsExact(destination);
                    Directory.Delete(destination, recursive: false);
                }
                catch { }
            }
        }
    }

    private static async Task DeleteDirectorySnapshotAsync(
        string source,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        DirectoryFingerprintSnapshot snapshot = await DirectoryFingerprint.CaptureAsync(source, cancellationToken);
        if (!snapshot.Sha256.Equals(expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.DeleteDirectorySnapshotAsync.01"), sourceText => new InvalidOperationException(sourceText));

        foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => !entry.IsDirectory))
        {
            string sourceFile = ResolveSnapshotPath(source, entry.RelativePath);
            await using SecureFileLease lease = SecureFileLease.Open(sourceFile);
            if (!IsWithin(lease.FinalPath, source))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.DeleteDirectorySnapshotAsync.02"), sourceText => new UnauthorizedAccessException(sourceText));
            string currentHash = await lease.ComputeSha256Async(cancellationToken);
            if (!currentHash.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.DeleteDirectorySnapshotAsync.03", (entry.RelativePath)), sourceText => new InvalidOperationException(sourceText));
            lease.DeleteOnClose();
        }

        foreach (DirectoryFingerprintEntry entry in snapshot.Entries.Where(entry => entry.IsDirectory)
                     .OrderByDescending(entry => entry.RelativePath.Count(c => c == '/'))
                     .ThenByDescending(entry => entry.RelativePath.Length))
        {
            string directory = ResolveSnapshotPath(source, entry.RelativePath);
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.DeleteDirectorySnapshotAsync.04"), sourceText => new UnauthorizedAccessException(sourceText));
            SecureDirectoryDeletion.DeleteEmpty(directory);
        }
        SecureDirectoryDeletion.DeleteEmpty(source);
    }

    private static string ResolveSnapshotPath(string root, string relative)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        string result = Path.GetFullPath(Path.Combine(fullRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!result.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ResolveSnapshotPath.01"), sourceText => new UnauthorizedAccessException(sourceText));
        return result;
    }

    private static void EnsureTreeHasNoReparsePoints(string root)
    {
        if (Validation.ContainsReparsePoint(root)) throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.EnsureTreeHasNoReparsePoints.01"), sourceText => new UnauthorizedAccessException(sourceText));
        _ = EnumerateTreeWithoutReparsePoints(root);
    }

    private static void DeleteDirectoryContentsExact(string root)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Validation.IsSafeExactTarget(fullRoot) || Validation.ContainsReparsePoint(fullRoot))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.DeleteDirectoryContentsExact.01"), sourceText => new UnauthorizedAccessException(sourceText));
        string[] entries = EnumerateTreeWithoutReparsePoints(fullRoot);
        foreach (string file in entries.Where(File.Exists)) File.Delete(file);
        foreach (string directory in entries.Where(Directory.Exists).OrderByDescending(value => value.Length))
            Directory.Delete(directory, recursive: false);
    }

    private static string[] EnumerateTreeWithoutReparsePoints(string root)
    {
        List<string> entries = [];
        Stack<string> pending = new();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            if (Validation.ContainsReparsePoint(directory))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.EnumerateTreeWithoutReparsePoints.01", (directory)), sourceText => new UnauthorizedAccessException(sourceText));
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.EnumerateTreeWithoutReparsePoints.02", (entry)), sourceText => new UnauthorizedAccessException(sourceText));
                entries.Add(entry);
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
        }
        return [.. entries];
    }

    private static string SafeName(string name)
    {
        string safe = string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return string.IsNullOrWhiteSpace(safe) ? "item" : safe[..Math.Min(safe.Length, 120)];
    }

    private static string GetIncidentRoot(Guid incidentId)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.QuarantineRoot));
        string incident = Path.GetFullPath(Path.Combine(root, incidentId.ToString("D")));
        if (!incident.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.GetIncidentRoot.01"), sourceText => new UnauthorizedAccessException(sourceText));
        return incident;
    }

    private async Task InitializeManifestAsync(CancellationToken cancellationToken)
    {
        byte[] content = SerializeManifest(_manifest);
        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        _incidentTrustStore.RegisterPending(_manifest, sha256);
        await WriteManifestAtomicAsync(_manifestPath, content, _manifest.RequestedBySid, cancellationToken);
        _incidentTrustStore.CommitManifestUpdate(_manifest.IncidentId, sha256);
    }

    private Task PersistManifestAsync(CancellationToken cancellationToken) =>
        PersistTrustedManifestAsync(_manifestPath, _manifest, cancellationToken);

    private async Task PersistTrustedManifestAsync(
        string manifestPath,
        QuarantineManifest manifest,
        CancellationToken cancellationToken)
    {
        byte[] content = SerializeManifest(manifest);
        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        _incidentTrustStore.BeginManifestUpdate(manifest.IncidentId, sha256);
        await WriteManifestAtomicAsync(manifestPath, content, manifest.RequestedBySid, cancellationToken);
        _incidentTrustStore.CommitManifestUpdate(manifest.IncidentId, sha256);
    }

    internal async Task<QuarantineManifest> LoadTrustedManifestAsync(
        Guid incidentId,
        string incidentRoot,
        string manifestPath,
        CancellationToken cancellationToken,
        string? requestedBySidForTest = null)
    {
        IncidentTrustRecord trust = _incidentTrustStore.GetRequired(incidentId);
        _incidentStateSecurity.EnsureProtectedPath(incidentRoot);
        _incidentStateSecurity.EnsureProtectedPath(manifestPath);
        QuarantineManifest manifest;
        string actualSha256;
        await using (SecureFileLease lease = SecureFileLease.Open(manifestPath))
        {
            if (lease.Length is <= 0 or > MaximumManifestBytes)
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.LoadTrustedManifestAsync.01"), sourceText => new InvalidDataException(sourceText));
            actualSha256 = await lease.ComputeSha256Async(cancellationToken);
            if (!trust.AcceptsManifestHash(actualSha256))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.LoadTrustedManifestAsync.02"), sourceText => new UnauthorizedAccessException(sourceText));
            manifest = await lease.ReadJsonAsync<QuarantineManifest>(cancellationToken);
        }

        if (manifest.SchemaVersion != "1" || !trust.MatchesIdentity(manifest) || manifest.IncidentId != incidentId)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.LoadTrustedManifestAsync.03"), sourceText => new InvalidDataException(sourceText));
        string expectedRequester = requestedBySidForTest ?? _requestedBySid;
        if (!manifest.RequestedBySid.Equals(expectedRequester, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.LoadTrustedManifestAsync.04"), sourceText => new UnauthorizedAccessException(sourceText));
        if (manifest.Records is null || manifest.Records.Count > 64 ||
            manifest.Records.Any(record => record is null || record.ActionId == Guid.Empty) ||
            manifest.Records.Select(record => record.ActionId).Distinct().Count() != manifest.Records.Count)
        {
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.LoadTrustedManifestAsync.05"), sourceText => new InvalidDataException(sourceText));
        }

        // The registry keeps both committed and pending hashes. If a broker crashed after the
        // atomic file replacement, accepting only that pre-authorized pending hash recovers safely.
        if (!actualSha256.Equals(trust.ManifestSha256, StringComparison.OrdinalIgnoreCase))
            _incidentTrustStore.CommitManifestUpdate(incidentId, actualSha256);
        _incidentStateSecurity.EnsureProtectedSubtree(incidentRoot);
        return manifest;
    }

    private static byte[] SerializeManifest(QuarantineManifest manifest)
    {
        byte[] content = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonFile.Options);
        if (content.Length is <= 0 or > MaximumManifestBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.SerializeManifest.01"), sourceText => new InvalidDataException(sourceText));
        return content;
    }

    private static async Task WriteManifestAtomicAsync(
        string path,
        byte[] content,
        string requestedBySid,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.WriteManifestAtomicAsync.01"), sourceText => new InvalidOperationException(sourceText));
        MachineStateSecurity.EnsureProtectedPath(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (FileStream stream = new(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 64 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(content, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, fullPath, overwrite: true);
            MachineStateSecurity.ProtectManifestFile(fullPath, requestedBySid);
        }
        finally
        {
            if (File.Exists(temporary) && !Validation.ContainsReparsePoint(temporary))
            {
                try { File.Delete(temporary); } catch { }
            }
        }
    }

    private static async Task<ProcessResult> RunEncodedPowerShellAsync(
        string fixedScript,
        IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$PSModuleAutoLoadingPreference='All';" + fixedScript));
        return await RunProcessAsync(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand", encoded],
            cancellationToken,
            environment);
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        IEnumerable<string> arguments,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        startInfo.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        startInfo.Environment["SystemRoot"] = windows;
        startInfo.Environment["WINDIR"] = windows;
        startInfo.Environment["COMSPEC"] = Path.Combine(system, "cmd.exe");
        startInfo.Environment["PATH"] = system;
        startInfo.Environment["TEMP"] = AppPaths.BrokerTemporaryRoot;
        startInfo.Environment["TMP"] = AppPaths.BrokerTemporaryRoot;
        startInfo.Environment["ProgramFiles"] = programFiles;
        startInfo.Environment["PROGRAMDATA"] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        startInfo.Environment["PSModulePath"] = string.Join(Path.PathSeparator,
            Path.Combine(system, "WindowsPowerShell", "v1.0", "Modules"),
            Path.Combine(programFiles, "WindowsPowerShell", "Modules"));
        foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);
        if (environment is not null)
        {
            foreach ((string key, string value) in environment) startInfo.Environment[key] = value;
        }
        using Process process = new() { StartInfo = startInfo };
        process.Start();
        Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            cancellationToken.ThrowIfCancellationRequested();
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.RunProcessAsync.01", (Path.GetFileName(fileName))), sourceText => new TimeoutException(sourceText));
        }
        return new ProcessResult(process.ExitCode, await output, await error);
    }

    private sealed record ProcessResult(int ExitCode, string Output, string Error);
}
