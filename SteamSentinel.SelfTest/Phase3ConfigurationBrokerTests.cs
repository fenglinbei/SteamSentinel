using System.Reflection;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // All adapter calls and every payload/manifest write in this suite use memory-only
    // fakes. No real certificate store, proxy, ProgramData directory or service is changed.
    private static async Task TestPhase3ConfigurationBrokerAsync()
    {
        using var certificate = CreateTrustProxyRoot("CN=SteamSentinel inert configuration Broker fixture");
        BoundCertificateTarget unbound = new()
        {
            TargetUserSid = CertificateFixtureSid,
            StoreLocation = "CurrentUser",
            StoreName = "Root",
            DerSha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData))
        };
        BoundCertificateBackup original = BoundCertificateRepair.CreateBackup(unbound, certificate.RawData,
            [new() { Id = 11, ValueBase64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("inert public metadata\0")) }]);
        RemediationAction CertificateAction(string? relatedPath = null, string? writer = null) => new()
        {
            Type = RemediationActionType.RemoveBoundCertificate,
            BoundCertificate = original.Target,
            Target = BoundConfigurationTargetNames.Certificate(original.Target),
            ConfigurationEvidenceRuleId = "INERT-CONFIG-CERT",
            RelatedFilePath = relatedPath,
            RelatedFileSha256 = writer,
            IsKnownMalware = true,
            ConfidenceScore = 100
        };
        RemediationAction action = CertificateAction();
        ConfigurationBrokerFixture fixture = CreateConfigurationBrokerFixture(action, original, BoundConfigurationEvidenceCatalog.Embedded);
        Check("配置Broker 内置规则为空时客户端高分恶意标签不授权",
            RejectsConfiguration(() => InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationAction", action)) &&
            fixture.Certificates.Reads == 0 && fixture.Payloads.Content.Count == 0);

        string writerHash = new('8', 64), writerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "inert-component.txt");
        action = CertificateAction(writerPath, writerHash);
        BoundConfigurationEvidenceCatalog writerCatalog = ConfigurationFixtureCatalog(action, writerHash);
        fixture = CreateConfigurationBrokerFixture(action, original, writerCatalog);
        Check("配置Broker 已确认写入者不能省略隔离前置",
            RejectsConfiguration(() => InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationPlan", fixture.Plan)));
        RemediationAction quarantine = new() { Type = RemediationActionType.QuarantineFile, Target = writerPath, ExpectedSha256 = writerHash };
        RemediationPlan withWriter = new() { RequestedBySid = CertificateFixtureSid, Actions = [quarantine, action] };
        InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationPlan", withWriter);
        Check("配置Broker 删除客户端依赖后仍要求同哈希隔离前置", action.DependsOnActionIds.Count == 0 &&
            RemediationDependencies.Build(withWriter.Actions)[action.ActionId].Contains(quarantine.ActionId));

        action = CertificateAction();
        fixture = CreateConfigurationBrokerFixture(action, original);
        Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText> prepared = await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine,
            "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        QuarantineRecord record = fixture.Manifest.Records.Single();
        string preparedPath = record.ConfigurationBackupPath!;
        Check("配置Broker 完整备份和受信manifest先持久化再允许任何变更", prepared.Count == 0 &&
            fixture.Payloads.Content.Count == 1 && fixture.Persisted.Count == 1 && fixture.Certificates.DeleteCalls == 0 &&
            !record.ConfigurationMutationAttempted && !record.MutationConfirmed);
        fixture.Certificates.BeforeDelete = _ => Check("配置Broker 删除前attempt已在清单持久化",
            fixture.Persisted.Last().Records.Single().ConfigurationMutationAttempted && fixture.Payloads.Content.ContainsKey(preparedPath));
        await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", action, CancellationToken.None);
        Check("配置Broker 精确证书删除成功后才确认mutation", record.MutationConfirmed && fixture.Certificates.DeleteMutations == 1 &&
            fixture.Certificates.Entries.Count == 0 && fixture.Persisted.Last().Records.Single().MutationConfirmed);
        Check("配置Broker 禁止同一配置动作重放", await RejectsConfigurationAsync(async () =>
            await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", action, CancellationToken.None)) && fixture.Certificates.DeleteMutations == 1);
        InvokeConfiguration<object?>(fixture.Engine, "SetConfigurationRollbackContext", fixture.Manifest, fixture.ManifestPath);
        InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationRecord", record, fixture.IncidentRoot);
        await InvokeConfiguration<Task>(fixture.Engine, "RestoreConfigurationAsync", record, fixture.IncidentRoot, CancellationToken.None);
        BoundConfigurationBackupDocument restoredCertificate = fixture.Payloads.ReadCurrent(record);
        Check("配置Broker 受信原事件恢复完整公开状态且保留旧版本", fixture.Certificates.RestoreMutations == 1 &&
            fixture.Certificates.Entries.Single().DerBase64 == original.DerBase64 && restoredCertificate.RestoreCompleted &&
            fixture.Payloads.Content.ContainsKey(preparedPath) && record.ConfigurationBackupPath != preparedPath && !record.RolledBack);

        fixture = CreateConfigurationBrokerFixture(CertificateAction(), original);
        await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        record = fixture.Manifest.Records.Single();
        InvokeConfiguration<object?>(fixture.Engine, "SetConfigurationRollbackContext", fixture.Manifest, fixture.ManifestPath);
        await InvokeConfiguration<Task>(fixture.Engine, "RestoreConfigurationAsync", record, fixture.IncidentRoot, CancellationToken.None);
        Check("配置Broker 仅预备但整链跳过的记录回滚不导入不删除", fixture.Certificates.DeleteCalls == 0 &&
            fixture.Certificates.RestoreCalls == 0 && fixture.Certificates.Entries.Count == 1);
        string safePath = record.ConfigurationBackupPath!;
        record.ConfigurationBackupPath = Path.Combine(fixture.IncidentRoot, "outside.json");
        int reads = fixture.Payloads.Reads;
        Check("配置Broker 备份必须位于动作ID和SHA绑定的固定版本路径",
            RejectsConfiguration(() => InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationRecord", record, fixture.IncidentRoot)) && fixture.Payloads.Reads == reads);
        record.ConfigurationBackupPath = safePath;
        fixture.Payloads.Content[safePath][0] ^= 1;
        Check("配置Broker 保护备份字节与manifest哈希不符先拒绝",
            RejectsConfiguration(() => InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationRecord", record, fixture.IncidentRoot)) && fixture.Certificates.RestoreCalls == 0);

        fixture = CreateConfigurationBrokerFixture(CertificateAction(), original);
        fixture.FailPersist = true;
        prepared = await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        Check("配置Broker 备份提交失败返回动作失败且无系统变更", prepared.ContainsKey(fixture.Plan.Actions.Single().ActionId) &&
            fixture.Certificates.DeleteCalls == 0 && fixture.Proxy.Writes == 0 && await RejectsConfigurationAsync(async () =>
                await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", fixture.Plan.Actions.Single(), CancellationToken.None)));

        fixture = CreateConfigurationBrokerFixture(CertificateAction(), original);
        await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        fixture.FailPersist = true;
        Check("配置Broker 临写attempt日志提交失败禁止进入删除原语", await RejectsConfigurationAsync(async () =>
            await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", fixture.Plan.Actions.Single(), CancellationToken.None)) &&
            fixture.Certificates.DeleteCalls == 0 && !fixture.Persisted.Last().Records.Single().ConfigurationMutationAttempted);

        BoundProxyTarget proxyTarget = ConfigurationFixtureProxyTarget();
        RemediationAction proxyAction = new()
        {
            Type = RemediationActionType.RestoreBoundProxyConfiguration,
            BoundProxy = proxyTarget,
            Target = BoundConfigurationTargetNames.Proxy(proxyTarget),
            ConfigurationEvidenceRuleId = "INERT-CONFIG-PROXY"
        };
        fixture = CreateConfigurationBrokerFixture(proxyAction, original);
        await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        record = fixture.Manifest.Records.Single();
        preparedPath = record.ConfigurationBackupPath!;
        fixture.Proxy.FailNotify = true;
        Check("配置Broker 代理通知失败仍返回失败", await RejectsConfigurationAsync(async () =>
            await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", proxyAction, CancellationToken.None)));
        BoundConfigurationBackupDocument partiallyApplied = fixture.Payloads.ReadCurrent(record);
        Check("配置Broker finally保留实际Applied代理状态且不冒充全成功", fixture.Proxy.Writes == 1 &&
            partiallyApplied.Proxy is
            {
                WriteAttempted: true, WriteSucceeded: true, ReadBackMatched: true, SettingsChangedNotified: false,
                MutationState: BoundProxyMutationState.Applied
            } && !record.MutationConfirmed &&
            record.ConfigurationMutationAttempted && record.ConfigurationBackupPath != preparedPath && fixture.Payloads.Content.ContainsKey(preparedPath));
        fixture.Proxy.FailNotify = false;
        InvokeConfiguration<object?>(fixture.Engine, "SetConfigurationRollbackContext", fixture.Manifest, fixture.ManifestPath);
        await InvokeConfiguration<Task>(fixture.Engine, "RestoreConfigurationAsync", record, fixture.IncidentRoot, CancellationToken.None);
        Check("配置Broker 通知失败后的已确认After仅按精确原值恢复", fixture.Proxy.Writes == 2 &&
            BoundProxyRepair.SnapshotsEqual(fixture.Proxy.Current, proxyTarget.Before) &&
            fixture.Payloads.ReadCurrent(record).Proxy is { MutationState: BoundProxyMutationState.Restored, RestoreReadBackMatched: true } &&
            fixture.Persisted.Last().Records.Single().ConfigurationBackupSha256 == record.ConfigurationBackupSha256);

        fixture = CreateConfigurationBrokerFixture(proxyAction, original);
        await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", proxyAction, CancellationToken.None);
        record = fixture.Manifest.Records.Single();
        fixture.Proxy.Current = new()
        {
            Flags = 3,
            ProxyServer = new() { Present = true, Value = "later-legitimate.invalid:8080" },
            PolicyGuard = proxyTarget.Before.PolicyGuard
        };
        BoundProxySnapshot legitimate = fixture.Proxy.Current;
        InvokeConfiguration<object?>(fixture.Engine, "SetConfigurationRollbackContext", fixture.Manifest, fixture.ManifestPath);
        Check("配置Broker 回滚拒绝覆盖后来的合法代理配置", await RejectsConfigurationAsync(async () =>
            await InvokeConfiguration<Task>(fixture.Engine, "RestoreConfigurationAsync", record, fixture.IncidentRoot, CancellationToken.None)) &&
            fixture.Proxy.Writes == 1 && ReferenceEquals(legitimate, fixture.Proxy.Current) && !record.RolledBack);
        Check("配置Broker 任意拷贝记录不能代替受信manifest原记录",
            RejectsConfiguration(() => InvokeConfiguration<object?>(fixture.Engine, "ValidateConfigurationRecord",
                JsonSerializer.Deserialize<QuarantineRecord>(JsonSerializer.Serialize(record, JsonFile.Options), JsonFile.Options)!, fixture.IncidentRoot)));

        fixture = CreateConfigurationBrokerFixture(proxyAction, original);
        await InvokeConfiguration<Task<Dictionary<Guid, SteamSentinel.Core.Reporting.MessageText>>>(fixture.Engine, "PrepareConfigurationBackupsAsync", fixture.Plan, CancellationToken.None);
        record = fixture.Manifest.Records.Single();
        string previousPath = record.ConfigurationBackupPath!, previousHash = record.ConfigurationBackupSha256!;
        fixture.Proxy.AfterWrite = () => fixture.FailPersist = true;
        bool uncertainJournal = false;
        try { await InvokeConfiguration<Task<SteamSentinel.Core.Reporting.MessageText>>(fixture.Engine, "ExecuteConfigurationActionAsync", proxyAction, CancellationToken.None); }
        catch (ConfigurationExecutionUncertainException) { uncertainJournal = true; }
        Check("配置Broker 写入后提交失败报告执行未知并保留旧可信完整字节", uncertainJournal &&
            fixture.Proxy.Writes == 1 && record.ConfigurationBackupPath != previousPath && fixture.Payloads.Content.ContainsKey(previousPath) &&
            Convert.ToHexString(SHA256.HashData(fixture.Payloads.Content[previousPath])) == previousHash &&
            fixture.Persisted.Last().Records.Single().ConfigurationBackupPath == previousPath &&
            fixture.Persisted.Last().Records.Single().ConfigurationMutationAttempted);
    }

    private static BoundConfigurationEvidenceCatalog ConfigurationFixtureCatalog(RemediationAction action, string? writer = null) => new([new()
    {
        Id = action.ConfigurationEvidenceRuleId!, ActionType = action.Type,
        TargetIdentitySha256 = BoundConfigurationEvidenceCatalog.IdentityFingerprint(action), SourceArtifactSha256 = new string('7', 64),
        EvidenceReference = "In-memory synthetic fixture only; never added to embedded production rules.", ConfirmedWriterSha256 = writer
    }]);

    private static BoundProxyTarget ConfigurationFixtureProxyTarget()
    {
        BoundProxyPolicyGuard guard = new() { Status = BoundProxyPolicyStatus.Unmanaged, Fingerprint = new string('A', 64), Detail = "Inert memory fixture" };
        return new()
        {
            TargetUserSid = CertificateFixtureSid,
            Before = new() { Flags = 5, AutoConfigUrl = new() { Present = true, Value = "https://inert.invalid/no-fetch.pac" }, PolicyGuard = guard },
            Desired = new() { Flags = 1, PolicyGuard = guard },
            ChangedFields = [BoundProxyField.Flags, BoundProxyField.AutoConfigUrl]
        };
    }

    private static ConfigurationBrokerFixture CreateConfigurationBrokerFixture(RemediationAction action, BoundCertificateBackup certificate,
        BoundConfigurationEvidenceCatalog? catalog = null)
    {
        RemediationPlan plan = new() { RequestedBySid = CertificateFixtureSid, Actions = [action] };
        QuarantineManifest manifest = new() { IncidentId = Guid.NewGuid(), PlanId = plan.PlanId, TrustId = Guid.NewGuid(), RequestedBySid = CertificateFixtureSid };
        string root = Path.Combine(AppPaths.QuarantineRoot, manifest.IncidentId.ToString("D"));
        ConfigurationBrokerFixture fixture = new()
        {
            Plan = plan,
            Manifest = manifest,
            IncidentRoot = root,
            ManifestPath = Path.Combine(root, "manifest.json"),
            Certificates = new(certificate),
            Proxy = new(action.BoundProxy?.Before ?? ConfigurationFixtureProxyTarget().Before)
        };
        fixture.Engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity(), catalog ?? ConfigurationFixtureCatalog(action),
            fixture.Certificates, fixture.Proxy, () => CertificateFixtureSid, fixture.Payloads, (current, _, token) =>
            {
                token.ThrowIfCancellationRequested();
                if (fixture.FailPersist) throw new IOException("Inert injected manifest commit failure");
                fixture.Persisted.Add(JsonSerializer.Deserialize<QuarantineManifest>(JsonSerializer.Serialize(current, JsonFile.Options), JsonFile.Options)!);
                return Task.CompletedTask;
            });
        foreach ((string field, object value) in new (string, object)[]
        {
            ("_manifest", manifest), ("_manifestPath", fixture.ManifestPath), ("_incidentRoot", root),
            ("_requestedBySid", CertificateFixtureSid), ("_persistOwnManifest", true)
        }) typeof(BrokerEngine).GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(fixture.Engine, value);
        return fixture;
    }

    private static T InvokeConfiguration<T>(BrokerEngine engine, string method, params object[] arguments)
    {
        try { return (T)typeof(BrokerEngine).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(engine, arguments)!; }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        { ExceptionDispatchInfo.Capture(ex.InnerException).Throw(); throw; }
    }

    private static bool RejectsConfiguration(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidDataException or IOException or InvalidOperationException) { return true; }
    }

    private static async Task<bool> RejectsConfigurationAsync(Func<Task> action)
    {
        try { await action(); return false; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidDataException or IOException or InvalidOperationException) { return true; }
    }

    private sealed class ConfigurationBrokerFixture
    {
        public BrokerEngine Engine { get; set; } = null!;
        public RemediationPlan Plan { get; init; } = null!;
        public QuarantineManifest Manifest { get; init; } = null!;
        public string IncidentRoot { get; init; } = "";
        public string ManifestPath { get; init; } = "";
        public FakeBoundCertificateStore Certificates { get; init; } = null!;
        public ConfigurationFixtureProxySettings Proxy { get; init; } = null!;
        public ConfigurationFixturePayloads Payloads { get; } = new();
        public List<QuarantineManifest> Persisted { get; } = [];
        public bool FailPersist { get; set; }
    }

    private sealed class ConfigurationFixtureProxySettings(BoundProxySnapshot initial) : IBoundProxySettings
    {
        public BoundProxySnapshot Current = initial;
        public int Writes;
        public bool FailNotify;
        public Action? AfterWrite;
        public BoundProxySnapshot ReadCurrentUserLan() => Current;
        public void WriteCurrentUserLan(BoundProxySnapshot desired, IReadOnlyList<BoundProxyField> fields) { Writes++; Current = desired; AfterWrite?.Invoke(); }
        public void NotifySettingsChanged() { if (FailNotify) throw new IOException("Inert injected notification failure"); }
        public void RefreshSettings() { }
    }

    private sealed class ConfigurationFixturePayloads : IBoundConfigurationPayloadStorage
    {
        public Dictionary<string, byte[]> Content { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int Reads;
        public Task WriteVersionAsync(string incidentRoot, string path, byte[] content, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (Content.TryGetValue(path, out byte[]? old) && !old.SequenceEqual(content)) throw new IOException("Inert immutable version conflict");
            Content.TryAdd(path, content.ToArray());
            return Task.CompletedTask;
        }
        public Task<BoundConfigurationBackupDocument> ReadVersionAsync(string incidentRoot, string path, string sha256, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Reads++;
            byte[] bytes = Content[path];
            if (bytes.Length is <= 0 or > BrokerEngine.MaximumConfigurationBackupBytes || Convert.ToHexString(SHA256.HashData(bytes)) != sha256)
                throw new UnauthorizedAccessException("Inert payload size or digest mismatch");
            return Task.FromResult(JsonSerializer.Deserialize<BoundConfigurationBackupDocument>(bytes, JsonFile.Options)!);
        }
        public BoundConfigurationBackupDocument ReadCurrent(QuarantineRecord record) =>
            ReadVersionAsync("", record.ConfigurationBackupPath!, record.ConfigurationBackupSha256!, CancellationToken.None).GetAwaiter().GetResult();
    }
}
