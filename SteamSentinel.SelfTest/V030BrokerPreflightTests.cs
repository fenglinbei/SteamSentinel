using System.IO;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030BrokerPreflightAsync(string root)
    {
        string directory = Path.Combine(root, "v030-broker-preflight");
        Directory.CreateDirectory(directory);
        string inertFile = Path.Combine(directory, "inert-document.txt");
        const string content = "Inert preflight fixture. Never executed or quarantined.";
        await File.WriteAllTextAsync(inertFile, content);
        BrokerEngine engine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity());
        int executionCalls = 0;
        Task<RemediationRunResult> ObserveExecution()
        {
            executionCalls++;
            return Task.FromResult(new RemediationRunResult());
        }

        // Even the accepted first action is only validated. No real execution callback is used by these tests.
        RemediationAction first = new() { Type = RemediationActionType.RestoreSecurityControls, Target = "Windows Security" };
        RemediationAction refused = new() { Type = RemediationActionType.QuarantineFile, Target = inertFile };
        RemediationPlan plan = new() { Actions = [first, refused] };
        RemediationRunResult result = await BrokerExecutionBoundary.RunAsync(plan,
            () => engine.ValidateBeforeExecution(plan), ObserveExecution);
        Check("Broker预检查 后续隔离缺少哈希时整批尚未开始", result.Disposition == RemediationRunDisposition.NotStarted &&
            !result.Success && result.Actions.Count == 0 && executionCalls == 0);
        Check("Broker预检查 拒绝收据绑定完整计划且未创建隔离记录", result.PlanId == plan.PlanId &&
            result.PlanIdentitySha256 == RemediationPlanIdentity.Fingerprint(plan) && result.ManifestPath is null &&
            result.CompletedAtUtc >= result.StartedAtUtc && await File.ReadAllTextAsync(inertFile) == content);
        string serialized = JsonSerializer.Serialize(result, JsonFile.Options);
        Check("Broker预检查 保留可翻译的原始拒绝原因", result.Errors.Count == 1 && result.ErrorMessages?.Count == 1 &&
            serialized.Contains("Backend.Exception", StringComparison.Ordinal) &&
            serialized.Contains("Backend.Broker.BrokerEngine.ValidateQuarantinePath.03", StringComparison.Ordinal));

        string receiptPath = Path.Combine(directory, $"refused-{plan.PlanId:N}.json");
        await using (BrokerResultChannel channel = BrokerResultChannel.CreateForTesting(receiptPath))
        {
            await channel.WriteAsync(result);
            Check("Broker预检查 拒绝收据写入后关闭重复写入口", channel.HasWritten && !channel.CanWrite);
        }
        RemediationRunResult persisted = JsonSerializer.Deserialize<RemediationRunResult>(
            await File.ReadAllTextAsync(receiptPath), JsonFile.Options)!;
        ProtectedRemediationResultReader.Validate(plan, persisted);
        Check("Broker预检查 持久化NotStarted收据可通过恢复校验", persisted.Disposition == RemediationRunDisposition.NotStarted);
        RemediationPlan changed = new() { PlanId = plan.PlanId, Actions = [first] };
        Check("Broker预检查 同PlanId但计划内容变化不能借用拒绝收据", RejectsPreflightReceipt(changed, persisted));

        RemediationPlan invalidPlan = new() { SchemaVersion = "unsupported-fixture", Actions = [first] };
        RemediationRunResult invalidResult = await BrokerExecutionBoundary.RunAsync(invalidPlan,
            () => engine.ValidateBeforeExecution(invalidPlan), ObserveExecution);
        ProtectedRemediationResultReader.Validate(invalidPlan, invalidResult);
        Check("Broker预检查 计划格式拒绝同样明确未开始", invalidResult.Disposition == RemediationRunDisposition.NotStarted && executionCalls == 0);

        // Force the final configuration-plan SID check to fail through the existing in-memory adapters.
        ConfigurationFixtureProxySettings proxy = new(new BoundProxySnapshot());
        ConfigurationFixturePayloads payloads = new();
        int persistenceCalls = 0;
        BrokerEngine configurationEngine = new(new FixtureTrustStore(null), new FixtureIncidentStateSecurity(),
            BoundConfigurationEvidenceCatalog.Embedded, new FakeBoundCertificateStore(), proxy,
            () => string.Empty, payloads, (_, _, _) => { persistenceCalls++; return Task.CompletedTask; });
        RemediationPlan configurationPlan = new() { Actions = [first] };
        RemediationRunResult configurationResult = await BrokerExecutionBoundary.RunAsync(configurationPlan,
            () => configurationEngine.ValidateBeforeExecution(configurationPlan), ObserveExecution);
        Check("Broker预检查 最终配置计划校验也在执行边界之前", configurationResult.Disposition == RemediationRunDisposition.NotStarted &&
            executionCalls == 0 && persistenceCalls == 0 && proxy.Writes == 0 && payloads.Content.Count == 0 &&
            JsonSerializer.Serialize(configurationResult, JsonFile.Options).Contains(
                "Backend.Broker.BrokerBoundConfigurationActions.RequireConfigurationSid.01", StringComparison.Ordinal));
        ProtectedRemediationResultReader.Validate(configurationPlan, configurationResult);

        RemediationRunResult accepted = new();
        RemediationRunResult returned = await BrokerExecutionBoundary.RunAsync(configurationPlan,
            () => engine.ValidateBeforeExecution(configurationPlan), () => { executionCalls++; return Task.FromResult(accepted); });
        Check("Broker预检查 合法计划只进入执行一次且保留执行结果", executionCalls == 1 && ReferenceEquals(accepted, returned));

        foreach (Exception failure in new Exception[]
        {
            MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerEngine.ValidateQuarantinePath.03"),
                text => new UnauthorizedAccessException(text)),
            new IOException("Inert journal failure after possible mutation"),
            new OperationCanceledException("Inert cancellation after possible mutation")
        })
        {
            int beforeCalls = executionCalls;
            RemediationRunResult before = await BrokerExecutionBoundary.RunAsync(configurationPlan,
                () => throw failure, ObserveExecution);
            ProtectedRemediationResultReader.Validate(configurationPlan, before);
            Check("Broker预检查 边界前异常无需按文字分类 " + failure.GetType().Name,
                before.Disposition == RemediationRunDisposition.NotStarted && executionCalls == beforeCalls);
            Exception? propagated = null;
            try
            {
                await BrokerExecutionBoundary.RunAsync(configurationPlan, () => { }, () =>
                {
                    executionCalls++;
                    return Task.FromException<RemediationRunResult>(failure);
                });
            }
            catch (Exception ex) { propagated = ex; }
            Check("Broker预检查 边界后同一异常交回ExecutionUnknown处理 " + failure.GetType().Name,
                ReferenceEquals(failure, propagated) && executionCalls == beforeCalls + 1);
        }
        RemediationRunResult unknown = new()
        {
            PlanId = plan.PlanId,
            PlanIdentitySha256 = RemediationPlanIdentity.Fingerprint(plan),
            CompletedAtUtc = DateTimeOffset.UtcNow,
            Disposition = RemediationRunDisposition.ExecutionUnknown,
            Errors = ["Inert failure after possible mutation"]
        };
        Check("Broker预检查 未知空收据仍不能冒充未执行", RejectsPreflightReceipt(plan, unknown));
    }

    private static bool RejectsPreflightReceipt(RemediationPlan plan, RemediationRunResult result)
    {
        try { ProtectedRemediationResultReader.Validate(plan, result); return false; }
        catch (InvalidDataException) { return true; }
    }
}
