using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SteamSentinel.Core.Utilities;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Broker;
using SteamSentinel.App.Services;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestPhase3DependenciesAsync(string root)
    {
        string file = Path.Combine(root, "phase3-inert-component.txt"), other = Path.Combine(root, "phase3-independent.txt");
        Guid chain = Guid.NewGuid();
        RemediationAction stop = new() { Type = RemediationActionType.StopHostProcess, Target = other, RelatedFilePath = file, ProcessId = 43210, ProcessStartedAtUtc = DateTimeOffset.UtcNow };
        RemediationAction persist = new() { Type = RemediationActionType.DisableService, Target = "InertFixtureService", RelatedFilePath = file };
        RemediationAction quarantine = new() { Type = RemediationActionType.QuarantineFile, Target = file };
        RemediationAction repair = new() { Type = RemediationActionType.RestoreBoundProxyConfiguration, Target = "inert-proxy", RelatedFilePath = file };
        RemediationAction independent = new() { Type = RemediationActionType.QuarantineFile, Target = Path.Combine(root, "elsewhere.txt") };
        List<RemediationAction> actions = [repair, quarantine, persist, independent, stop];
        RemediationDependencies.AssignAndOrder(actions);
        var graph = RemediationDependencies.Build(actions);
        Check("第三批依赖 关联配置必须依赖停宿主解除持久化隔离", new[] { stop, persist, quarantine }.All(a => graph[repair.ActionId].Contains(a.ActionId)));
        Check("第三批依赖 独立目标不会被错误连入感染链", graph[independent.ActionId].Count == 0 && independent.ChainId is null);
        Check("第三批依赖 规划器保留拓扑顺序与同一关联链", actions.IndexOf(stop) < actions.IndexOf(persist) && actions.IndexOf(persist) < actions.IndexOf(quarantine) && actions.IndexOf(quarantine) < actions.IndexOf(repair) && stop.ChainId == repair.ChainId);
        List<RemediationActionResult> results = [new() { ActionId = stop.ActionId, Success = false, ExecutionStatus = RemediationExecutionStatus.Failed },
            new() { ActionId = persist.ActionId, Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded, VerificationStatus = RemediationVerificationStatus.Verified },
            new() { ActionId = quarantine.ActionId, Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded, VerificationStatus = RemediationVerificationStatus.NoResidual }];
        Check("第三批依赖 同批前置失败不会被其他成功掩盖", RemediationDependencies.Unmet(repair.ActionId, graph, results).SequenceEqual([stop.ActionId]));
        stop.DependsOnActionIds.Clear(); persist.DependsOnActionIds.Clear(); quarantine.DependsOnActionIds.Clear(); repair.DependsOnActionIds.Clear();
        foreach (RemediationAction action in actions) action.ChainId = null;
        var inferred = RemediationDependencies.Build(actions);
        Check("第三批依赖 客户端删除链ID和前置列表仍重建依赖", inferred[repair.ActionId].Contains(stop.ActionId) && inferred[repair.ActionId].Contains(quarantine.ActionId));
        foreach (RemediationAction failure in new[] { stop, persist, quarantine })
        {
            List<Guid> calls = []; RemediationRunResult run = new();
            await BrokerActionSequencer.RunAsync(new() { Actions = actions }, run, new Dictionary<Guid, string>(),
                (action, _) =>
                {
                    calls.Add(action.ActionId);
                    return action.ActionId == failure.ActionId ? Task.FromException<string>(new IOException("inert fixture refusal")) : Task.FromResult("inert success");
                }, (_, result, _) => { result.VerificationStatus = result.Success ? RemediationVerificationStatus.Verified : RemediationVerificationStatus.Unknown; return Task.CompletedTask; },
                _ => Task.CompletedTask);
            Check("第三批Broker顺序 " + failure.Type + "失败时不调用配置adapter", !calls.Contains(repair.ActionId) &&
                run.Actions.Single(r => r.ActionId == repair.ActionId).ExecutionStatus == RemediationExecutionStatus.SkippedDependency);
            Check("第三批Broker顺序 " + failure.Type + "失败保留独立链和逐项结果", calls.Contains(independent.ActionId) && run.Actions.Count == actions.Count && run.Errors.Count > 0);
        }
        List<Guid> preparationCalls = []; RemediationRunResult preparationRun = new();
        await BrokerActionSequencer.RunAsync(new() { Actions = actions }, preparationRun, new Dictionary<Guid, string> { [repair.ActionId] = "inert backup unavailable" },
            (a, _) => { preparationCalls.Add(a.ActionId); return Task.FromResult("inert"); },
            (_, r, _) => { r.VerificationStatus = RemediationVerificationStatus.Verified; return Task.CompletedTask; }, _ => Task.CompletedTask);
        Check("第三批Broker顺序 配置备份失败时整条相关链尚未变更", preparationCalls.SequenceEqual([independent.ActionId]) &&
            preparationRun.Actions.Single(r => r.ActionId == stop.ActionId).ExecutionStatus == RemediationExecutionStatus.SkippedDependency);
        List<Guid> pendingCalls = []; RemediationRunResult pendingRun = new();
        await BrokerActionSequencer.RunAsync(new() { Actions = actions }, pendingRun, new Dictionary<Guid, string>(),
            (a, _) => { pendingCalls.Add(a.ActionId); return Task.FromResult("inert"); },
            (a, r, _) => { r.VerificationStatus = a == stop ? RemediationVerificationStatus.PendingReboot : RemediationVerificationStatus.Verified; return Task.CompletedTask; }, _ => Task.CompletedTask);
        Check("第三批Broker顺序 请求返回成功但前置仍待重启时不修配置", !pendingCalls.Contains(repair.ActionId) && !pendingCalls.Contains(quarantine.ActionId));
        RemediationRunResult journalFailureRun = new();
        await BrokerActionSequencer.RunAsync(new() { Actions = [repair] }, journalFailureRun, new Dictionary<Guid, string>(),
            (_, _) => Task.FromException<string>(new ConfigurationExecutionUncertainException("inert journal incomplete", new IOException("inert"))),
            (_, r, _) => { r.VerificationStatus = RemediationVerificationStatus.Unknown; return Task.CompletedTask; }, _ => Task.CompletedTask);
        Check("第三批Broker顺序 已可能改值但最新日志提交失败保留ExecutionUnknown", journalFailureRun.Actions.Single().ExecutionStatus == RemediationExecutionStatus.ExecutionUnknown);
        string writerHash = new string('C', 64);
        RemediationAction aliasStop = new() { Type = RemediationActionType.StopProcess, Target = other, ExpectedSha256 = writerHash };
        RemediationAction aliasRepair = new() { Type = repair.Type, Target = "different identity label", RelatedFilePath = file, RelatedFileSha256 = writerHash };
        Check("第三批Broker顺序 同一已确认hash改路径不能拆掉前置", RemediationDependencies.Build([aliasStop, aliasRepair])[aliasRepair.ActionId].Contains(aliasStop.ActionId));
        RemediationAction explicitFirst = new() { Type = RemediationActionType.StopProcess, Target = "first", ChainId = chain };
        RemediationAction explicitSecond = new() { Type = RemediationActionType.StopProcess, Target = "second", ChainId = chain, DependsOnActionIds = [explicitFirst.ActionId] };
        explicitFirst.DependsOnActionIds.Add(explicitSecond.ActionId);
        Check("第三批依赖 循环图拒绝", ThrowsPhase3(() => RemediationDependencies.Build([explicitFirst, explicitSecond], false)));
        Check("第三批依赖 缺失前置ID拒绝", ThrowsPhase3(() => RemediationDependencies.Build([new() { ActionId = Guid.NewGuid(), Target = "missing", DependsOnActionIds = [Guid.NewGuid()] }])));
        Check("第三批依赖 逆序计划在执行前拒绝", ThrowsPhase3(() => RemediationDependencies.Build([repair, quarantine, stop])));
        RemediationActionResult skipped = new() { ActionId = repair.ActionId, ExecutionStatus = RemediationExecutionStatus.SkippedDependency };
        Phase3CountingProbe probe = new();
        RemediationVerification verification = new(probe);
        await verification.ObserveAsync(repair, skipped, 1);
        await verification.CompleteAsync(new() { Actions = [repair] }, new() { Actions = [skipped] }, secondPassDelay: TimeSpan.Zero);
        Check("第三批依赖 跳过动作不以当前无残留冒充执行成功", probe.Calls == 0 && skipped.VerificationStatus == RemediationVerificationStatus.Unknown && !skipped.Success);
        RemediationAction directory = new() { Type = RemediationActionType.QuarantineDirectory, Target = Path.Combine(root, "directory") };
        RemediationAction childStop = new() { Type = RemediationActionType.StopProcess, Target = Path.Combine(directory.Target, "child.txt") };
        Check("第三批依赖 目录隔离包含已规划的子项前置", RemediationDependencies.Build([childStop, directory])[directory.ActionId].Contains(childStop.ActionId));
        QuarantineRecord configurationRecord = new() { ActionId = repair.ActionId, Type = repair.Type };
        QuarantineRecord fileRecord = new() { ActionId = quarantine.ActionId, Type = quarantine.Type };
        QuarantineRecord serviceRecord = new() { ActionId = persist.ActionId, Type = persist.Type };
        QuarantineManifest orderedManifest = new() { ActionOrder = [persist.ActionId, quarantine.ActionId, repair.ActionId], Records = [configurationRecord, serviceRecord, fileRecord] };
        Check("第三批回滚 预先备份配置仍按实际计划逆序恢复", RemediationDependencies.RollbackOrder(orderedManifest).SequenceEqual([configurationRecord, fileRecord, serviceRecord]));
        Check("第三批回滚 缺少专用动作顺序不能猜测逆序", ThrowsPhase3(() => RemediationDependencies.RollbackOrder(new() { Records = [configurationRecord] })));

        BoundCertificateTarget certificate = new() { TargetUserSid = "S-1-5-21-1-2-3-1001", StoreLocation = "CurrentUser", StoreName = "Root", DerSha256 = new string('A', 64), PropertiesSha256 = new string('B', 64) };
        RemediationAction certAction = new() { Type = RemediationActionType.RemoveBoundCertificate, Target = "inert certificate", BoundCertificate = certificate, ConfigurationEvidenceRuleId = "inert-reviewed-rule", IsKnownMalware = true, ConfidenceScore = 100 };
        Check("第三批授权 名称自签或客户端已知恶意标志不能开放删除", ThrowsPhase3(() => BoundConfigurationEvidenceCatalog.Embedded.Authorize(certAction)) && BoundConfigurationEvidenceCatalog.Embedded.Count == 0);
        BoundConfigurationEvidenceCatalog fixtureCatalog = new([new()
        {
            Id = certAction.ConfigurationEvidenceRuleId!, ActionType = certAction.Type,
            TargetIdentitySha256 = BoundConfigurationEvidenceCatalog.IdentityFingerprint(certAction),
            SourceArtifactSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("inert-only-evidence"))),
            EvidenceReference = "In-memory self-test fixture; not a real malware rule."
        }]);
        Check("第三批授权 精确规则要求独立证据身份与动作类型", fixtureCatalog.Authorize(certAction).Id == certAction.ConfigurationEvidenceRuleId);
        RemediationAction wrongStore = new()
        {
            Type = certAction.Type,
            Target = certAction.Target,
            ConfigurationEvidenceRuleId = certAction.ConfigurationEvidenceRuleId,
            BoundCertificate = new() { TargetUserSid = certificate.TargetUserSid, StoreLocation = "LocalMachine", StoreName = certificate.StoreName, DerSha256 = certificate.DerSha256, PropertiesSha256 = certificate.PropertiesSha256 }
        };
        Check("第三批授权 同名同DER但物理来源不同不能沿用规则", ThrowsPhase3(() => fixtureCatalog.Authorize(wrongStore)));
        Check("第三批授权 公共计划构建仍不能注入测试规则", ThrowsPhase3(() => BoundConfigurationPlanBuilder.Build([certAction])));

        RemediationPlan pending = new() { Actions = [independent] };
        RemediationRunResult incomplete = new() { PlanId = pending.PlanId, PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(pending), Success = true, CompletedAtUtc = DateTimeOffset.UtcNow };
        Check("第三批结果 缺少动作的成功结果不能解除未知执行", ThrowsPhase3(() => ProtectedRemediationResultReader.Validate(pending, incomplete)));
        RemediationRunResult rejected = new() { PlanId = pending.PlanId, PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(pending), Success = false, Disposition = RemediationRunDisposition.NotStarted, CompletedAtUtc = DateTimeOffset.UtcNow, Errors = ["fixture refusal before actions"] };
        ProtectedRemediationResultReader.Validate(pending, rejected);
        Check("第三批结果 管理员明确拒绝可记录为失败", !rejected.Success && rejected.Actions.Count == 0);
        Check("第三批结果 中途致命失败的空结果保持未知", ThrowsPhase3(() => ProtectedRemediationResultReader.Validate(pending,
            new() { PlanId = pending.PlanId, PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(pending), CompletedAtUtc = DateTimeOffset.UtcNow, Disposition = RemediationRunDisposition.ExecutionUnknown, Errors = ["fixture fatal error after possible mutation"] })));
        RemediationPlan originalIdentity = new()
        {
            Actions = [new()
        {
            Type = RemediationActionType.RemoveRegistryValue, Target = "inert registry display target",
            RegistryHive = "HKCU", RegistryView = "Registry64", RegistryKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            RegistryValueName = "OriginalFixture", ExpectedValueData = "original inert value",
            ProcessStartedAtUtc = DateTimeOffset.UtcNow
        }]
        };
        RemediationRunResult boundResult = new()
        {
            PlanId = originalIdentity.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(originalIdentity),
            Disposition = RemediationRunDisposition.Completed,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Success = true,
            Actions = [new() { ActionId = originalIdentity.Actions[0].ActionId, Type = originalIdentity.Actions[0].Type,
                Target = originalIdentity.Actions[0].Target, Success = true, ExecutionStatus = RemediationExecutionStatus.Succeeded }]
        };
        RemediationPlan roundTrip = JsonSerializer.Deserialize<RemediationPlan>(JsonSerializer.Serialize(originalIdentity, JsonFile.Options), JsonFile.Options)!;
        ProtectedRemediationResultReader.Validate(roundTrip, boundResult);
        Check("第三批结果 完整计划经病例JSON往返仍接受对应受保护结果", RemediationPlanIdentity.Fingerprint(roundTrip) == boundResult.PlanIdentitySha256);
        foreach ((string field, JsonNode value) in new (string, JsonNode)[]
        {
            ("RegistryValueName", JsonValue.Create("NowAbsentFixture")),
            ("RegistryHive", JsonValue.Create("HKLM")),
            ("ExpectedValueData", JsonValue.Create("different inert value")),
            ("ProcessStartedAtUtc", JsonValue.Create(DateTimeOffset.UtcNow.AddHours(-1)))
        })
        {
            JsonNode edited = JsonSerializer.SerializeToNode(originalIdentity, JsonFile.Options)!;
            edited["Actions"]![0]![field] = value;
            RemediationPlan altered = edited.Deserialize<RemediationPlan>(JsonFile.Options)!;
            Check("第三批结果 同计划与动作ID改写" + field + "不能套用旧成功结果",
                ThrowsPhase3(() => ProtectedRemediationResultReader.Validate(altered, boundResult)));
        }
        RemediationRunResult legacyResult = new()
        {
            PlanId = originalIdentity.PlanId,
            Success = true,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Actions = boundResult.Actions
        };
        Check("第三批结果 缺少完整计划身份的旧结果不能支撑病例复验", ThrowsPhase3(() => ProtectedRemediationResultReader.Validate(originalIdentity, legacyResult)));
        RemediationClient reopenedClient = new();
        reopenedClient.RestoreUnresolvedPlan(pending);
        bool blocked = false;
        try { await reopenedClient.ExecuteAsync(new()); }
        catch (InvalidOperationException) { blocked = true; }
        Check("第三批结果 重开客户端恢复未决计划后先阻止新处置且不发起UAC", reopenedClient.HasUnresolvedExecution && blocked);
    }

    private static bool ThrowsPhase3(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or UnauthorizedAccessException or ArgumentException) { return true; }
    }

    private sealed class Phase3CountingProbe : IRemediationStateProbe
    {
        internal int Calls;
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult(new RemediationVerificationObservation { Status = RemediationVerificationStatus.NoResidual }); }
    }
}
