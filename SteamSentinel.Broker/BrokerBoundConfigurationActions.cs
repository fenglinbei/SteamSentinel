using SteamSentinel.Core.Reporting;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    internal const int MaximumConfigurationBackupBytes = 768 * 1024;
    private readonly BoundConfigurationEvidenceCatalog _configurationCatalog = BoundConfigurationEvidenceCatalog.Embedded;
    private readonly IBoundCertificateStore _configurationCertificateStore = new WindowsBoundCertificateStore();
    private readonly IBoundProxySettings _configurationProxySettings = new WindowsBoundProxySettings();
    private readonly Func<string> _configurationCurrentSid = ReadConfigurationCurrentSid;
    private readonly IBoundConfigurationPayloadStorage _configurationPayloads = new ProtectedConfigurationPayloadStorage();
    private readonly Func<QuarantineManifest, string, CancellationToken, Task>? _configurationPersistForTest;
    private readonly HashSet<Guid> _preparedConfigurationActions = [];
    private QuarantineManifest? _configurationRollbackManifest;
    private string? _configurationRollbackManifestPath;

    // Only the test assembly can supply adapters, an evidence catalog and in-memory persistence.
    // No request field, case file or configuration setting can select these dependencies.
    internal BrokerEngine(IIncidentTrustStore trust, IIncidentStateSecurity security,
        BoundConfigurationEvidenceCatalog catalog, IBoundCertificateStore certificates, IBoundProxySettings proxy,
        Func<string> currentSid, IBoundConfigurationPayloadStorage payloads,
        Func<QuarantineManifest, string, CancellationToken, Task> persistForTest) : this(trust, security)
    {
        _configurationCatalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _configurationCertificateStore = certificates ?? throw new ArgumentNullException(nameof(certificates));
        _configurationProxySettings = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _configurationCurrentSid = currentSid ?? throw new ArgumentNullException(nameof(currentSid));
        _configurationPayloads = payloads ?? throw new ArgumentNullException(nameof(payloads));
        _configurationPersistForTest = persistForTest ?? throw new ArgumentNullException(nameof(persistForTest));
    }

    private static bool IsDedicatedConfiguration(RemediationActionType type) => type is
        RemediationActionType.RemoveBoundCertificate or RemediationActionType.RestoreBoundProxyConfiguration;

    private void ValidateConfigurationAction(RemediationAction action)
    {
        if (!IsDedicatedConfiguration(action.Type) || action.ActionId == Guid.Empty ||
            string.IsNullOrWhiteSpace(action.ConfigurationEvidenceRuleId) || action.ConfigurationEvidenceRuleId.Length > 128)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ValidateConfigurationAction.01"), sourceText => new InvalidDataException(sourceText));
        string sid;
        string expectedTarget;
        if (action.Type == RemediationActionType.RemoveBoundCertificate && action.BoundCertificate is { } certificate && action.BoundProxy is null)
        {
            BoundCertificateTarget target = BoundCertificateRepair.ValidateTarget(certificate, requireProperties: true);
            sid = target.TargetUserSid;
            expectedTarget = BoundConfigurationTargetNames.Certificate(target);
        }
        else if (action.Type == RemediationActionType.RestoreBoundProxyConfiguration && action.BoundProxy is { } proxy && action.BoundCertificate is null)
        {
            BoundProxyRepair.ValidateTarget(proxy);
            sid = proxy.TargetUserSid;
            expectedTarget = BoundConfigurationTargetNames.Proxy(proxy);
        }
        else throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ValidateConfigurationAction.02"), sourceText => new InvalidDataException(sourceText));
        RequireConfigurationSid(sid);
        if (!string.Equals(action.Target, expectedTarget, StringComparison.Ordinal))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ValidateConfigurationAction.03"), sourceText => new InvalidDataException(sourceText));
        _ = _configurationCatalog.Authorize(action);
    }

    private void ValidateConfigurationPlan(RemediationPlan plan)
    {
        RemediationAction[] configurations = plan.Actions.Where(a => IsDedicatedConfiguration(a.Type)).ToArray();
        if (configurations.Length > 16 || configurations.Select(a => a.Target).Distinct(StringComparer.Ordinal).Count() != configurations.Length)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ValidateConfigurationPlan.01"), sourceText => new InvalidDataException(sourceText));
        RequireConfigurationSid(plan.RequestedBySid);
        var dependencies = RemediationDependencies.Build(plan.Actions);
        foreach (RemediationAction action in configurations)
        {
            ValidateConfigurationAction(action);
            BoundConfigurationEvidenceRule rule = _configurationCatalog.Authorize(action);
            if (rule.ConfirmedWriterSha256 is { } writer && !plan.Actions.Any(prerequisite =>
                prerequisite.Type == RemediationActionType.QuarantineFile &&
                string.Equals(prerequisite.ExpectedSha256, writer, StringComparison.OrdinalIgnoreCase) &&
                dependencies[action.ActionId].Contains(prerequisite.ActionId)))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ValidateConfigurationPlan.02"), sourceText => new UnauthorizedAccessException(sourceText));
        }
    }

    private async Task<Dictionary<Guid, MessageText>> PrepareConfigurationBackupsAsync(RemediationPlan plan, CancellationToken token)
    {
        ValidateConfigurationPlan(plan);
        _preparedConfigurationActions.Clear();
        Dictionary<Guid, MessageText> failures = [];
        foreach (RemediationAction action in plan.Actions.Where(a => IsDedicatedConfiguration(a.Type)))
        {
            try
            {
                token.ThrowIfCancellationRequested();
                ValidateConfigurationAction(action);
                if (_manifest.PlanId != plan.PlanId || _manifest.RequestedBySid != plan.RequestedBySid ||
                    _manifest.Records.Any(r => r.ActionId == action.ActionId))
                    throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.PrepareConfigurationBackupsAsync.01"), sourceText => new InvalidDataException(sourceText));
                BoundConfigurationBackupDocument document = new()
                {
                    PlanId = plan.PlanId,
                    IncidentId = _manifest.IncidentId,
                    ActionId = action.ActionId,
                    TargetUserSid = plan.RequestedBySid,
                    Type = action.Type,
                    OriginalTarget = action.Target,
                    ConfigurationEvidenceRuleId = action.ConfigurationEvidenceRuleId!,
                    RelatedFilePath = action.RelatedFilePath,
                    RelatedFileSha256 = action.RelatedFileSha256,
                    Certificate = action.Type == RemediationActionType.RemoveBoundCertificate
                        ? new BoundCertificateRepair(_configurationCertificateStore, _configurationCurrentSid).Capture(action.BoundCertificate!) : null,
                    Proxy = action.Type == RemediationActionType.RestoreBoundProxyConfiguration
                        ? new BoundProxyRepair(_configurationProxySettings, _configurationCurrentSid).Capture(action.BoundProxy!) : null
                };
                QuarantineRecord record = new()
                {
                    ActionId = action.ActionId,
                    Type = action.Type,
                    OriginalTarget = action.Target,
                    RelatedFilePath = action.RelatedFilePath,
                    RelatedFileSha256 = action.RelatedFileSha256,
                    ConfigurationEvidenceRuleId = action.ConfigurationEvidenceRuleId
                };
                byte[] content = SerializeConfigurationBackup(document);
                string hash = Convert.ToHexString(SHA256.HashData(content));
                string path = ConfigurationBackupPath(_incidentRoot, action.ActionId, hash);
                await _configurationPayloads.WriteVersionAsync(_incidentRoot, path, content, token).ConfigureAwait(false);
                record.ConfigurationBackupPath = path;
                record.ConfigurationBackupSha256 = hash;
                _manifest.Records.Add(record);
                await PersistConfigurationManifestAsync(_manifest, _manifestPath, token).ConfigureAwait(false);
                _preparedConfigurationActions.Add(action.ActionId);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                failures[action.ActionId] = RemediationVerification.Limit(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.PrepareConfigurationBackupsAsync.02") + MessageExceptions.Describe(ex), 1700);
            }
        }
        return failures;
    }

    private async Task<MessageText> ExecuteConfigurationActionAsync(RemediationAction action, CancellationToken token)
    {
        ValidateConfigurationAction(action);
        if (!_preparedConfigurationActions.Contains(action.ActionId))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ExecuteConfigurationActionAsync.01"), sourceText => new InvalidOperationException(sourceText));
        QuarantineRecord record = _manifest.Records.Single(r => r.ActionId == action.ActionId);
        if (record.ConfigurationMutationAttempted || record.MutationConfirmed || record.RolledBack)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ExecuteConfigurationActionAsync.02"), sourceText => new InvalidOperationException(sourceText));
        BoundConfigurationBackupDocument document = await ReadConfigurationBackupAsync(record, _incidentRoot, _manifest, token).ConfigureAwait(false);
        RequireSameConfigurationAction(action, ConfigurationActionFrom(document));
        token.ThrowIfCancellationRequested();
        record.ConfigurationMutationAttempted = true;
        await PersistConfigurationManifestAsync(_manifest, _manifestPath, token).ConfigureAwait(false);
        Exception? operationFailure = null;
        try
        {
            token.ThrowIfCancellationRequested();
            if (document.Certificate is { } certificate)
                new BoundCertificateRepair(_configurationCertificateStore, _configurationCurrentSid).Remove(action.BoundCertificate!, certificate);
            else
                new BoundProxyRepair(_configurationProxySettings, _configurationCurrentSid).Apply(action.BoundProxy!, document.Proxy!);
            record.MutationConfirmed = true;
            return document.Certificate is not null
                ? MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ExecuteConfigurationActionAsync.03")
                : MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ExecuteConfigurationActionAsync.04");
        }
        catch (Exception ex) { operationFailure = ex; throw; }
        finally
        {
            try { await PersistConfigurationVersionAsync(record, document, _incidentRoot, _manifest, _manifestPath, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception journalFailure)
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ExecuteConfigurationActionAsync.05"), sourceText => new ConfigurationExecutionUncertainException(sourceText,
                operationFailure is null ? journalFailure : new AggregateException(operationFailure, journalFailure)));
            }
        }
    }

    // Called immediately after LoadTrustedManifestAsync, before validating rollback records.
    private void SetConfigurationRollbackContext(QuarantineManifest manifest, string manifestPath)
    {
        RequireConfigurationSid(manifest.RequestedBySid);
        if (manifest.IncidentId == Guid.Empty || manifest.PlanId == Guid.Empty ||
            !PathsEquivalent(manifestPath, Path.Combine(GetIncidentRoot(manifest.IncidentId), "manifest.json")))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.SetConfigurationRollbackContext.01"), sourceText => new InvalidDataException(sourceText));
        _configurationRollbackManifest = manifest;
        _configurationRollbackManifestPath = manifestPath;
    }

    private void ValidateConfigurationRecord(QuarantineRecord record, string incidentRoot)
    {
        (QuarantineManifest manifest, _) = RequireConfigurationRollbackContext(record, incidentRoot);
        _ = ReadConfigurationBackupAsync(record, incidentRoot, manifest, CancellationToken.None).GetAwaiter().GetResult();
    }

    private async Task RestoreConfigurationAsync(QuarantineRecord record, string incidentRoot, CancellationToken token)
    {
        (QuarantineManifest manifest, string manifestPath) = RequireConfigurationRollbackContext(record, incidentRoot);
        BoundConfigurationBackupDocument document = await ReadConfigurationBackupAsync(record, incidentRoot, manifest, token).ConfigureAwait(false);
        // Merely preparing a backup never changes a certificate or proxy. The outer rollback
        // can close this inactive record without importing or rewriting its original state.
        if (!record.ConfigurationMutationAttempted && !record.MutationConfirmed) return;
        token.ThrowIfCancellationRequested();
        document.RestoreAttempted = true;
        await PersistConfigurationVersionAsync(record, document, incidentRoot, manifest, manifestPath, token).ConfigureAwait(false);
        Exception? operationFailure = null;
        try
        {
            token.ThrowIfCancellationRequested();
            if (document.Certificate is { } certificate)
                new BoundCertificateRepair(_configurationCertificateStore, _configurationCurrentSid).Restore(certificate);
            else
                new BoundProxyRepair(_configurationProxySettings, _configurationCurrentSid).Restore(document.Proxy!);
            document.RestoreCompleted = true;
        }
        catch (Exception ex) { operationFailure = ex; throw; }
        finally
        {
            try { await PersistConfigurationVersionAsync(record, document, incidentRoot, manifest, manifestPath, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception journalFailure)
            {
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.RestoreConfigurationAsync.01"), sourceText => new ConfigurationExecutionUncertainException(sourceText,
                operationFailure is null ? journalFailure : new AggregateException(operationFailure, journalFailure)));
            }
        }
    }

    private (QuarantineManifest Manifest, string Path) RequireConfigurationRollbackContext(QuarantineRecord record, string incidentRoot)
    {
        if (_configurationRollbackManifest is not { } manifest || _configurationRollbackManifestPath is not { } path ||
            !manifest.Records.Any(r => ReferenceEquals(r, record)) || !PathsEquivalent(incidentRoot, GetIncidentRoot(manifest.IncidentId)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.RequireConfigurationRollbackContext.01"), sourceText => new UnauthorizedAccessException(sourceText));
        return (manifest, path);
    }

    private async Task<BoundConfigurationBackupDocument> ReadConfigurationBackupAsync(QuarantineRecord record, string incidentRoot,
        QuarantineManifest manifest, CancellationToken token)
    {
        if (!IsDedicatedConfiguration(record.Type) || record.ActionId == Guid.Empty ||
            !Validation.IsHexSha256(record.ConfigurationBackupSha256) || record.ConfigurationBackupPath is null ||
            string.IsNullOrWhiteSpace(record.ConfigurationEvidenceRuleId) || record.ConfigurationEvidenceRuleId.Length > 128 ||
            record.MutationConfirmed && !record.ConfigurationMutationAttempted ||
            !PathsEquivalent(incidentRoot, GetIncidentRoot(manifest.IncidentId)) ||
            !PathsEquivalent(record.ConfigurationBackupPath, ConfigurationBackupPath(incidentRoot, record.ActionId, record.ConfigurationBackupSha256!)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ReadConfigurationBackupAsync.01"), sourceText => new InvalidDataException(sourceText));
        RequireConfigurationSid(manifest.RequestedBySid);
        BoundConfigurationBackupDocument document = await _configurationPayloads.ReadVersionAsync(incidentRoot,
            record.ConfigurationBackupPath, record.ConfigurationBackupSha256!, token).ConfigureAwait(false);
        if (document.SchemaVersion != "1" || document.PlanId != manifest.PlanId || document.IncidentId != manifest.IncidentId ||
            document.ActionId != record.ActionId || document.Type != record.Type || document.TargetUserSid != manifest.RequestedBySid ||
            document.OriginalTarget != record.OriginalTarget || document.ConfigurationEvidenceRuleId != record.ConfigurationEvidenceRuleId ||
            document.RelatedFilePath != record.RelatedFilePath || document.RelatedFileSha256 != record.RelatedFileSha256 ||
            document.RestoreCompleted && !document.RestoreAttempted)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ReadConfigurationBackupAsync.02"), sourceText => new UnauthorizedAccessException(sourceText));
        RemediationAction restoredAction = ConfigurationActionFrom(document);
        ValidateConfigurationAction(restoredAction);
        return document;
    }

    private static RemediationAction ConfigurationActionFrom(BoundConfigurationBackupDocument document)
    {
        BoundCertificateTarget? certificate = null;
        BoundProxyTarget? proxy = null;
        if (document.Type == RemediationActionType.RemoveBoundCertificate && document.Certificate is { } publicBackup && document.Proxy is null)
            certificate = BoundCertificateRepair.ValidateBackup(publicBackup).Target;
        else if (document.Type == RemediationActionType.RestoreBoundProxyConfiguration && document.Proxy is { } proxyBackup && document.Certificate is null)
        {
            BoundProxyRepair.ValidateBackup(proxyBackup);
            proxy = new()
            {
                TargetUserSid = proxyBackup.TargetUserSid,
                Source = proxyBackup.Source,
                Before = proxyBackup.Before,
                Desired = proxyBackup.After,
                ChangedFields = [.. proxyBackup.ChangedFields]
            };
        }
        else throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ConfigurationActionFrom.01"), sourceText => new InvalidDataException(sourceText));
        if ((certificate?.TargetUserSid ?? proxy!.TargetUserSid) != document.TargetUserSid)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ConfigurationActionFrom.02"), sourceText => new UnauthorizedAccessException(sourceText));
        return new()
        {
            ActionId = document.ActionId,
            Type = document.Type,
            Target = document.OriginalTarget,
            ConfigurationEvidenceRuleId = document.ConfigurationEvidenceRuleId,
            RelatedFilePath = document.RelatedFilePath,
            RelatedFileSha256 = document.RelatedFileSha256,
            BoundCertificate = certificate,
            BoundProxy = proxy
        };
    }

    private static void RequireSameConfigurationAction(RemediationAction requested, RemediationAction restored)
    {
        string TargetState(RemediationAction action) => action.BoundCertificate is { } certificate
            ? JsonSerializer.Serialize(BoundCertificateRepair.ValidateTarget(certificate, true), JsonFile.Options)
            : JsonSerializer.Serialize(action.BoundProxy, JsonFile.Options);
        if (requested.ActionId != restored.ActionId || requested.Type != restored.Type || requested.Target != restored.Target ||
            requested.ConfigurationEvidenceRuleId != restored.ConfigurationEvidenceRuleId || requested.RelatedFilePath != restored.RelatedFilePath ||
            requested.RelatedFileSha256 != restored.RelatedFileSha256 || TargetState(requested) != TargetState(restored))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.RequireSameConfigurationAction.01"), sourceText => new InvalidDataException(sourceText));
    }

    private async Task PersistConfigurationVersionAsync(QuarantineRecord record, BoundConfigurationBackupDocument document, string incidentRoot,
        QuarantineManifest manifest, string manifestPath, CancellationToken token)
    {
        byte[] content = SerializeConfigurationBackup(document);
        string hash = Convert.ToHexString(SHA256.HashData(content));
        string path = ConfigurationBackupPath(incidentRoot, record.ActionId, hash);
        await _configurationPayloads.WriteVersionAsync(incidentRoot, path, content, token).ConfigureAwait(false);
        // Immutable versions keep the old manifest's referenced bytes available if the
        // process stops before the trusted manifest update is committed.
        record.ConfigurationBackupPath = path;
        record.ConfigurationBackupSha256 = hash;
        await PersistConfigurationManifestAsync(manifest, manifestPath, token).ConfigureAwait(false);
    }

    private Task PersistConfigurationManifestAsync(QuarantineManifest manifest, string path, CancellationToken token) =>
        _configurationPersistForTest is { } persist ? persist(manifest, path, token) : PersistTrustedManifestAsync(path, manifest, token);

    private static byte[] SerializeConfigurationBackup(BoundConfigurationBackupDocument document)
    {
        byte[] content = JsonSerializer.SerializeToUtf8Bytes(document, JsonFile.Options);
        if (content.Length is <= 0 or > MaximumConfigurationBackupBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.SerializeConfigurationBackup.01"), sourceText => new InvalidDataException(sourceText));
        return content;
    }

    private static string ConfigurationBackupPath(string incidentRoot, Guid actionId, string hash) =>
        Path.Combine(Path.GetFullPath(incidentRoot), "items", actionId.ToString("N"), "configuration-" + hash.ToUpperInvariant() + ".json");

    private void RequireConfigurationSid(string sid)
    {
        if (string.IsNullOrEmpty(sid) || sid.Length > 184 || new SecurityIdentifier(sid).Value != sid ||
            _configurationCurrentSid() != sid || !string.IsNullOrEmpty(_requestedBySid) && _requestedBySid != sid)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.RequireConfigurationSid.01"), sourceText => new UnauthorizedAccessException(sourceText));
    }

    private static string ReadConfigurationCurrentSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? string.Empty;
    }
}

internal sealed class ConfigurationExecutionUncertainException(string message, Exception cause) : IOException(message, cause);

internal sealed class BoundConfigurationBackupDocument
{
    public string SchemaVersion { get; init; } = "1";
    public Guid PlanId { get; init; }
    public Guid IncidentId { get; init; }
    public Guid ActionId { get; init; }
    public string TargetUserSid { get; init; } = string.Empty;
    public RemediationActionType Type { get; init; }
    public string OriginalTarget { get; init; } = string.Empty;
    public string ConfigurationEvidenceRuleId { get; init; } = string.Empty;
    public string? RelatedFilePath { get; init; }
    public string? RelatedFileSha256 { get; init; }
    public BoundCertificateBackup? Certificate { get; init; }
    public BoundProxyBackup? Proxy { get; init; }
    public bool RestoreAttempted { get; set; }
    public bool RestoreCompleted { get; set; }
}

internal interface IBoundConfigurationPayloadStorage
{
    Task WriteVersionAsync(string incidentRoot, string path, byte[] content, CancellationToken token);
    Task<BoundConfigurationBackupDocument> ReadVersionAsync(string incidentRoot, string path, string sha256, CancellationToken token);
}

internal sealed class ProtectedConfigurationPayloadStorage : IBoundConfigurationPayloadStorage
{
    public async Task WriteVersionAsync(string incidentRoot, string path, byte[] content, CancellationToken token)
    {
        if (content.Length is <= 0 or > BrokerEngine.MaximumConfigurationBackupBytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.WriteVersionAsync.01"), sourceText => new InvalidDataException(sourceText));
        MachineStateSecurity.EnsureProtectedPath(AppPaths.QuarantineRoot);
        MachineStateSecurity.EnsureProtectedPath(incidentRoot);
        string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        MachineStateSecurity.PreparePayloadDirectory(directory);
        string hash = Convert.ToHexString(SHA256.HashData(content));
        if (File.Exists(path))
        {
            _ = await ReadVersionAsync(incidentRoot, path, hash, token).ConfigureAwait(false);
            return;
        }
        await using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await stream.WriteAsync(content, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        MachineStateSecurity.ProtectPayloadFile(path);
        _ = await ReadVersionAsync(incidentRoot, path, hash, token).ConfigureAwait(false);
    }

    public async Task<BoundConfigurationBackupDocument> ReadVersionAsync(string incidentRoot, string path, string sha256, CancellationToken token)
    {
        MachineStateSecurity.EnsureProtectedPath(AppPaths.QuarantineRoot);
        MachineStateSecurity.EnsureProtectedPath(incidentRoot);
        MachineStateSecurity.EnsureProtectedPath(Path.Combine(incidentRoot, "items"));
        MachineStateSecurity.EnsureProtectedPath(Path.GetDirectoryName(path)!);
        MachineStateSecurity.EnsureProtectedPath(path);
        await using SecureFileLease lease = SecureFileLease.Open(path);
        if (lease.Length is <= 0 or > BrokerEngine.MaximumConfigurationBackupBytes ||
            !(await lease.ComputeSha256Async(token).ConfigureAwait(false)).Equals(sha256, StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerBoundConfigurationActions.ReadVersionAsync.01"), sourceText => new UnauthorizedAccessException(sourceText));
        BoundConfigurationBackupDocument document = await lease.ReadJsonAsync<BoundConfigurationBackupDocument>(token).ConfigureAwait(false);
        MachineStateSecurity.EnsureProtectedPath(path);
        return document;
    }
}
