using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0117SecurityAsync(string root)
    {
        string directory = Path.Combine(root, "v0117-security");
        Directory.CreateDirectory(directory);

        RemediationPlan completePlan = new()
        {
            Actions =
            {
                new RemediationAction
                {
                    Type = RemediationActionType.DeleteIncident,
                    Target = Guid.NewGuid().ToString("D"),
                    IncidentId = Guid.NewGuid().ToString("D")
                }
            }
        };
        JsonObject wire = JsonNode.Parse(JsonSerializer.Serialize(completePlan, JsonFile.Options))!.AsObject();
        foreach (string required in new[] { "PlanId", "CreatedAtUtc", "ExpiresAtUtc", "RequestedBySid" })
        {
            JsonObject missing = (JsonObject)wire.DeepClone();
            missing.Remove(required);
            bool rejected = false;
            try { _ = JsonSerializer.Deserialize<RemediationPlan>(missing, JsonFile.Options); }
            catch (JsonException) { rejected = true; }
            Check($"0.1.17 计划缺少 {required} 时不使用运行时默认值", rejected);
        }

        Guid incidentId = Guid.NewGuid(), planId = Guid.NewGuid(), trustId = Guid.NewGuid();
        DateTimeOffset created = DateTimeOffset.Parse("2026-09-05T01:02:03.4567890+00:00");
        QuarantineManifest manifest = new()
        {
            IncidentId = incidentId,
            PlanId = planId,
            TrustId = trustId,
            RequestedBySid = "S-1-5-21-1-2-3-1001",
            CreatedAtUtc = created
        };
        IncidentTrustRecord trust = new(
            incidentId, planId, trustId, manifest.RequestedBySid, created,
            new string('A', 64), new string('B', 64));
        Check("0.1.17 可信索引同时绑定事件、计划、SID、时间和随机身份",
            trust.MatchesIdentity(manifest) &&
            !trust.MatchesIdentity(new QuarantineManifest
            {
                IncidentId = incidentId,
                PlanId = planId,
                TrustId = trustId,
                RequestedBySid = "S-1-5-21-1-2-3-1002",
                CreatedAtUtc = created
            }));
        Check("0.1.17 可信索引仅接受已提交或预授权待提交清单哈希",
            trust.AcceptsManifestHash(new string('A', 64)) &&
            trust.AcceptsManifestHash(new string('B', 64)) &&
            !trust.AcceptsManifestHash(new string('C', 64)));

        string trustedRoot = Path.Combine(directory, incidentId.ToString("D"));
        Directory.CreateDirectory(trustedRoot);
        string trustedManifestPath = Path.Combine(trustedRoot, "manifest.json");
        await JsonFile.WriteAtomicAsync(trustedManifestPath, manifest);
        string trustedHash = await Hashing.Sha256FileExclusiveAsync(trustedManifestPath);
        IncidentTrustRecord indexed = trust with { ManifestSha256 = trustedHash, PendingManifestSha256 = null };
        FixtureTrustStore indexedStore = new(indexed);
        FixtureIncidentStateSecurity acceptedSecurity = new();
        BrokerEngine trustedLoader = new(indexedStore, acceptedSecurity);
        QuarantineManifest loaded = await trustedLoader.LoadTrustedManifestAsync(
            incidentId, trustedRoot, trustedManifestPath, CancellationToken.None, manifest.RequestedBySid);
        Check("0.1.17 temp 清单仅在可信索引和 ACL 门槛同时通过时载入",
            loaded.TrustId == trustId && acceptedSecurity.PathChecks == 2 && acceptedSecurity.TreeChecks == 1);

        manifest.Records.Add(new QuarantineRecord
        {
            ActionId = Guid.NewGuid(),
            Type = RemediationActionType.RemoveScheduledTask,
            OriginalTarget = "attacker self-declared fixture",
            Sha256 = new string('D', 64),
            TaskName = @"\SteamUpdate"
        });
        await JsonFile.WriteAtomicAsync(trustedManifestPath, manifest);
        bool forgedHashRejected = false;
        try
        {
            _ = await trustedLoader.LoadTrustedManifestAsync(
                incidentId, trustedRoot, trustedManifestPath, CancellationToken.None, manifest.RequestedBySid);
        }
        catch (UnauthorizedAccessException) { forgedHashRejected = true; }
        Check("0.1.17 自报载荷哈希的篡改清单仍因受保护索引哈希不符被拒", forgedHashRejected);

        manifest.Records.Clear();
        await JsonFile.WriteAtomicAsync(trustedManifestPath, manifest);
        bool writableAclRejected = false;
        try
        {
            _ = await new BrokerEngine(indexedStore, new FixtureIncidentStateSecurity(rejectPaths: true))
                .LoadTrustedManifestAsync(
                    incidentId, trustedRoot, trustedManifestPath, CancellationToken.None, manifest.RequestedBySid);
        }
        catch (UnauthorizedAccessException) { writableAclRejected = true; }
        bool missingIndexRejected = false;
        try
        {
            _ = await new BrokerEngine(new FixtureTrustStore(null), new FixtureIncidentStateSecurity())
                .LoadTrustedManifestAsync(
                    incidentId, trustedRoot, trustedManifestPath, CancellationToken.None, manifest.RequestedBySid);
        }
        catch (UnauthorizedAccessException) { missingIndexRejected = true; }
        Check("0.1.17 可写 ACL 或缺失可信索引的事件端到端 fail closed", writableAclRejected && missingIndexRejected);

        QuarantineManifest active = new()
        {
            Records = { new QuarantineRecord { ActionId = Guid.NewGuid(), OriginalTarget = "inert", RolledBack = false } }
        };
        Check("0.1.17 新隔离记录默认处于未确认突变状态", !active.Records[0].MutationConfirmed);
        bool activeDeleteRejected = false;
        try { BrokerEngine.EnsureIncidentDeletionAllowed(active); }
        catch (InvalidOperationException ex)
        {
            activeDeleteRejected = ex.Message.Contains("保留隔离", StringComparison.Ordinal) &&
                                   ex.Message.Contains("不要为了删除", StringComparison.Ordinal);
        }
        QuarantineManifest rolledBack = new()
        {
            Records = { new QuarantineRecord { ActionId = Guid.NewGuid(), OriginalTarget = "inert", RolledBack = true } }
        };
        bool rolledBackAllowed = true;
        try { BrokerEngine.EnsureIncidentDeletionAllowed(rolledBack); }
        catch { rolledBackAllowed = false; }
        Check("0.1.17 Broker 仅清理全部已回滚事件且不诱导恢复可疑样本", activeDeleteRejected && rolledBackAllowed);

        string deleteConfirmation = SteamSentinel.Broker.Program.BuildConfirmationMessage(new RemediationPlan
        {
            Actions = { new RemediationAction { Type = RemediationActionType.DeleteIncident, Target = incidentId.ToString("D") } }
        });
        string rollbackConfirmation = SteamSentinel.Broker.Program.BuildConfirmationMessage(new RemediationPlan
        {
            Actions = { new RemediationAction { Type = RemediationActionType.RollbackIncident, Target = incidentId.ToString("D") } }
        });
        Check("0.1.17 永久删除使用专属不可撤销确认",
            deleteConfirmation.Contains("永久删除", StringComparison.Ordinal) &&
            deleteConfirmation.Contains("无法撤销", StringComparison.Ordinal) &&
            deleteConfirmation.Contains("不要为了删除", StringComparison.Ordinal));
        Check("0.1.17 回滚确认说明重启风险与目录安全拒绝",
            rollbackConfirmation.Contains("可能重新启用", StringComparison.Ordinal) &&
            rollbackConfirmation.Contains("不会自动恢复整目录", StringComparison.Ordinal) &&
            BrokerEngine.DirectoryRollbackSafetyMessage.Contains("隔离副本保持不变", StringComparison.Ordinal));

        SecurityIdentifier fixtureSid = new("S-1-5-21-1-2-3-1001");
        DirectorySecurity incidentAcl = MachineStateSecurity.BuildProtectedDirectorySecurity(fixtureSid);
        FileSystemAccessRule[] incidentRules = incidentAcl.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        FileSecurity payloadAcl = MachineStateSecurity.BuildProtectedFileSecurity();
        FileSecurity metadataAcl = MachineStateSecurity.BuildProtectedFileSecurity(fixtureSid);
        Check("0.1.17 事件元数据按 SID 只读且权限不继承到载荷",
            incidentRules.Any(rule => rule.IdentityReference.Equals(fixtureSid) &&
                                      rule.InheritanceFlags == InheritanceFlags.None &&
                                      !InstallationSecurity.GrantsWrite(rule.FileSystemRights)) &&
            !payloadAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Any(rule => rule.IdentityReference.Equals(fixtureSid)) &&
            metadataAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Any(rule => rule.IdentityReference.Equals(fixtureSid) &&
                             !InstallationSecurity.GrantsWrite(rule.FileSystemRights) &&
                             (rule.FileSystemRights & FileSystemRights.ExecuteFile) == 0));

        Check("0.1.17 安装可加载文件白名单覆盖程序集和运行时配置",
            InstallationSecurity.IsLoadablePayloadPath("SteamSentinel.exe") &&
            InstallationSecurity.IsLoadablePayloadPath("lib\\fixture.dll") &&
            InstallationSecurity.IsLoadablePayloadPath("SteamSentinel.deps.json") &&
            InstallationSecurity.IsLoadablePayloadPath("SteamSentinel.runtimeconfig.json") &&
            InstallationSecurity.IsLoadablePayloadPath("SteamSentinel.exe.config") &&
            !InstallationSecurity.IsLoadablePayloadPath("docs\\THREAT-MODEL.md"));
        Check("0.1.17 仅允许根级固定 Inno 卸载器不在清单中",
            InstallationSecurity.IsAllowedUnlistedInstallFile("unins000.exe") &&
            !InstallationSecurity.IsAllowedUnlistedInstallFile("tools\\unins000.exe") &&
            !InstallationSecurity.IsAllowedUnlistedInstallFile("unins001.exe"));

        const string normalSoftwareSddl =
            "O:BAG:SYD:PAI(A;CI;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)" +
            "(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)";
        RegistrySecurity normalSoftwareAcl = new();
        normalSoftwareAcl.SetSecurityDescriptorSddlForm(normalSoftwareSddl);
        RegistrySecurity unsafeSoftwareAcl = new();
        unsafeSoftwareAcl.SetSecurityDescriptorSddlForm(
            "O:BAG:SYD:PAI(A;CI;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;BU)");
        Check("0.1.17 正常 Windows HKLM SOFTWARE 的可信 owner/CREATOR OWNER ACL 不被误拒",
            RegistryIncidentTrustStore.IsRegistrySecurityDescriptorProtected(
                normalSoftwareAcl, allowCreatorOwnerForTrustedOwner: true) &&
            !RegistryIncidentTrustStore.IsRegistrySecurityDescriptorProtected(
                normalSoftwareAcl, allowCreatorOwnerForTrustedOwner: false) &&
            !RegistryIncidentTrustStore.IsRegistrySecurityDescriptorProtected(
                unsafeSoftwareAcl, allowCreatorOwnerForTrustedOwner: true));

        string resultPath = Path.Combine(directory, "result-placeholder.json");
        await using (BrokerResultChannel first = BrokerResultChannel.CreateForTesting(resultPath))
        {
            bool duplicateRejected = false;
            try { await using BrokerResultChannel duplicate = BrokerResultChannel.CreateForTesting(resultPath); }
            catch (IOException) { duplicateRejected = true; }
            await first.WriteAsync(new RemediationRunResult { PlanId = planId, Success = true });
            Check("0.1.17 PlanId 结果占位以 CreateNew 原子拒绝并发执行", duplicateRejected && first.HasWritten);
        }
        bool replayRejected = false;
        try { await using BrokerResultChannel replay = BrokerResultChannel.CreateForTesting(resultPath); }
        catch (IOException) { replayRejected = true; }
        Check("0.1.17 已完成 PlanId 占位持久拒绝重放", replayRejected &&
            (await JsonFile.ReadAsync<RemediationRunResult>(resultPath)).PlanId == planId);

        string lockPath = Path.Combine(directory, "mutation.lock");
        bool firstLock = BrokerMutationLease.TryAcquireForTesting(lockPath, out BrokerMutationLease? mutation);
        bool concurrentLock = BrokerMutationLease.TryAcquireForTesting(lockPath, out BrokerMutationLease? duplicateMutation);
        duplicateMutation?.Dispose();
        mutation?.Dispose();
        bool recoveredLock = BrokerMutationLease.TryAcquireForTesting(lockPath, out BrokerMutationLease? recoveredMutation);
        recoveredMutation?.Dispose();
        Check("0.1.17 不同 PlanId 共用全局副作用锁且崩溃释放后可恢复", firstLock && !concurrentLock && recoveredLock);

        string emptyDirectory = Path.Combine(directory, "secure-delete-empty");
        Directory.CreateDirectory(emptyDirectory);
        SecureDirectoryDeletion.DeleteEmpty(emptyDirectory);
        Check("0.1.17 用户可写父路径中的空目录通过最终句柄绑定删除", !Directory.Exists(emptyDirectory));
    }

    private sealed class FixtureTrustStore(IncidentTrustRecord? record) : IIncidentTrustStore
    {
        private IncidentTrustRecord? _record = record;

        public void RegisterPending(QuarantineManifest manifest, string pendingManifestSha256)
        {
            _record = new IncidentTrustRecord(
                manifest.IncidentId,
                manifest.PlanId,
                manifest.TrustId,
                manifest.RequestedBySid,
                manifest.CreatedAtUtc,
                string.Empty,
                pendingManifestSha256);
        }

        public IncidentTrustRecord GetRequired(Guid incidentId) =>
            _record is { } value && value.IncidentId == incidentId
                ? value
                : throw new UnauthorizedAccessException("fixture missing protected index");

        public void BeginManifestUpdate(Guid incidentId, string nextManifestSha256)
        {
            IncidentTrustRecord current = GetRequired(incidentId);
            _record = current with { PendingManifestSha256 = nextManifestSha256 };
        }

        public void CommitManifestUpdate(Guid incidentId, string manifestSha256)
        {
            IncidentTrustRecord current = GetRequired(incidentId);
            if (!current.AcceptsManifestHash(manifestSha256)) throw new InvalidOperationException("fixture hash mismatch");
            _record = current with { ManifestSha256 = manifestSha256, PendingManifestSha256 = null };
        }

        public void Delete(Guid incidentId)
        {
            _ = GetRequired(incidentId);
            _record = null;
        }
    }

    private sealed class FixtureIncidentStateSecurity(bool rejectPaths = false) : IIncidentStateSecurity
    {
        public int PathChecks { get; private set; }
        public int TreeChecks { get; private set; }

        public void EnsureProtectedPath(string path)
        {
            PathChecks++;
            if (rejectPaths) throw new UnauthorizedAccessException("fixture writable ACL");
        }

        public void EnsureProtectedSubtree(string path)
        {
            TreeChecks++;
            if (rejectPaths) throw new UnauthorizedAccessException("fixture writable subtree ACL");
        }
    }
}
