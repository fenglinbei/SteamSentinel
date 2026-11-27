using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    // Inert actions and object fixtures only. PowerShell runs shadowed read commands or
    // Thread.Sleep; this suite never creates a firewall rule or executes a remediation.
    private static async Task TestFirewallVerificationBudgetAsync(string root)
    {
        string traceRoot = Path.Combine(root, "firewall-fixture-traces-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(traceRoot);
        RemediationAction firewall = new()
        {
            Type = RemediationActionType.AddProgramFirewallBlock,
            Target = Path.Combine(root, "never-created-firewall-target.exe")
        };
        RemediationAction cleanup = new()
        {
            Type = RemediationActionType.QuarantineFile,
            Target = firewall.Target,
            DependsOnActionIds = [firewall.ActionId]
        };
        Guid incident = Guid.NewGuid();
        Check("防火墙复验只有新增程序阻断使用15秒普通动作仍10秒",
            Enum.GetValues<RemediationActionType>().All(type => RemediationVerification.GetProbeTimeout(type) ==
                TimeSpan.FromSeconds(type == RemediationActionType.AddProgramFirewallBlock ? 15 : 10)) &&
            new CaseReverificationLimits().FirewallProbeTimeout == RemediationVerification.FirewallProbeTimeout &&
            new CaseReverificationLimits().ProbeTimeout == RemediationVerification.ProbeTimeout &&
            RemediationVerification.SecondPassBudget == TimeSpan.FromSeconds(45));

        // 使用可控虚拟时钟验证 15 秒 / 10 秒超时契约，同时保留并发测试结构。
        ManualTimeProvider slowClock = new();
        TaskCompletionSource slowPass1Waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource slowPass2Waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int slowObserveCalls = 0;
        Task<RemediationRunResult> slow = SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
        {
            int call = Interlocked.Increment(ref slowObserveCalls);
            Task delay = Task.Delay(TimeSpan.FromMilliseconds(11500), slowClock, token);
            if (call == 1) slowPass1Waiting.TrySetResult();
            else if (call == 2) slowPass2Waiting.TrySetResult();
            await delay;
            return new() { Status = RemediationVerificationStatus.Verified };
        }), complete: true, timeProvider: slowClock);
        Stopwatch timeoutClock = Stopwatch.StartNew();
        ManualTimeProvider timeoutVirtualClock = new();
        TaskCompletionSource timeoutWaiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<RemediationRunResult> timedOut = TimeoutSequenceAsync(timeoutVirtualClock, timeoutWaiting);
        ManualTimeProvider ordinaryClock = new();
        TaskCompletionSource ordinaryWaiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
        RemediationActionResult ordinary = new() { ExecutionStatus = RemediationExecutionStatus.Succeeded };
        Task ordinaryProbe = new RemediationVerification(new FirewallBudgetProbe(async (_, token) =>
        {
            Task delay = Task.Delay(TimeSpan.FromMilliseconds(11500), ordinaryClock, token);
            ordinaryWaiting.TrySetResult();
            await delay;
            return new() { Status = RemediationVerificationStatus.Verified };
        }), ordinaryClock).ObserveAsync(cleanup, ordinary, 1);
        long slowCaseRunnerElapsedMs = 0;

        using (CancellationTokenSource cancelled = new(TimeSpan.FromMilliseconds(100)))
        {
            ManualTimeProvider cancelClock = new();
            RemediationRunResult cancellation = await SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancelClock, token);
                return new() { Status = RemediationVerificationStatus.Verified };
            }), token: cancelled.Token, timeProvider: cancelClock);
            Check("防火墙完整调用取消保持Unknown且不执行后续隔离", cancellation.Actions.Count == 1 &&
                cancellation.Actions[0].VerificationStatus == RemediationVerificationStatus.Unknown);
        }
        foreach (RemediationVerificationStatus state in new[]
            { RemediationVerificationStatus.Unknown, RemediationVerificationStatus.ResidualDetected })
        {
            RemediationRunResult blocked = await SequenceAsync(new FirewallBudgetProbe((_, _) =>
                Task.FromResult(new RemediationVerificationObservation { Status = state })));
            Check("防火墙未验证仍阻止依赖隔离 " + state, blocked.Actions[0].Success &&
                blocked.Actions[1].ExecutionStatus == RemediationExecutionStatus.SkippedDependency);
        }

        // 先单独冷启动 1 次真实 powershell.exe 跑 exact，验证进程冷启与 CaseReadOnlyScriptRunner 端到端链路，
        // 并捕获 WindowsRemediationStateProbe 生成的只读谓词脚本。
        string[] fixtures = ["exact", "prefix-neighbor", "missing", "prefix-only", "case-only", "duplicate", "disabled",
            "allow", "inbound", "limited-profile", "program", "protocol", "port", "address", "service", "interface",
            "interface-type", "profile-disabled", "profile-missing", "profile-error", "provider-error"];
        string ruleName = $"SteamSentinel-{incident:N}-{firewall.ActionId:N}";
        string? capturedPredicateScript = null;
        string coldExactTrace = Path.Combine(traceRoot, "exact-" + Guid.NewGuid().ToString("N") + ".log");
        string? coldExactOutput = null;
        WindowsRemediationStateProbe coldExactProbe = new(async (value, token) =>
        {
            capturedPredicateScript = value;
            string fixtureScript = FirewallObjectFixture("exact", ruleName, firewall.Target);
            coldExactOutput = await CaseReadOnlyScriptRunner.RunAsync(TraceStage(coldExactTrace, "entry") + "try{" +
                fixtureScript + value + "}finally{" + TraceStage(coldExactTrace, "end") + "}", token);
            return coldExactOutput;
        }, incident);
        RemediationVerificationObservation coldExactObservation = await coldExactProbe.ObserveAsync(firewall, default);
        if (capturedPredicateScript is null)
            throw new InvalidOperationException("未能捕获防火墙验证谓词脚本。");

        // 与慢用例测试并发执行 1 次单进程 PowerShell 批跑：在独立局部作用域中依次运行全部 21 个 fixture 分支。
        Task<CaseVerificationEpisode> caseProbe = SlowCaseAsync();
        string sharedScriptBody = FirewallObjectFixtureBody(ruleName, firewall.Target) + capturedPredicateScript;
        string sharedBodyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(sharedScriptBody));
        string fixtureLiteralList = string.Join(",", fixtures.Select(f => $"'{f}'"));
        string batchScript = $$$$"""
            $shared=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{sharedBodyBase64}}}}'));
            $rs=[runspacefactory]::CreateRunspace();
            $rs.Open();
            try{
                $lines=[Collections.Generic.List[string]]::new();
                foreach($f in @({{{{fixtureLiteralList}}}})){
                    $ps=[powershell]::Create();
                    $ps.Runspace=$rs;
                    try{
                        $null=$ps.AddScript('$ProgressPreference=''SilentlyContinue'';$ErrorActionPreference=''Stop'';$fixture='''+$f+''';'+$shared,$true);
                        $ok='1';$val='';$err='';
                        try{
                            $res=@($ps.Invoke()|ForEach-Object{[string]$_});
                            if($ps.HadErrors){$ok='0';$err=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((($ps.Streams.Error|ForEach-Object{$_.ToString()}) -join '; ')))}
                            else{$val=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($res -join "`n").Trim()))}
                        }catch{$ok='0';$err=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message))}
                        $lines.Add($f+'|'+$ok+'|'+$val+'|'+$err)
                    }finally{$ps.Dispose()}
                }
                [string]::Join("`n",$lines)
            }finally{$rs.Dispose()}
            """;
        string? batchText = await CaseReadOnlyScriptRunner.RunAsync(batchScript, default);
        Dictionary<string, BatchFixtureResult> batchByFixture = new(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(batchText))
        {
            foreach (string rawLine in batchText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string[] parts = rawLine.Split('|');
                if (parts.Length != 4 || string.IsNullOrEmpty(parts[0])) continue;
                bool ok = parts[1] == "1";
                string? outputValue = ok ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[2])) : null;
                string? errorValue = parts[3].Length > 0 ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[3])) : null;
                batchByFixture[parts[0]] = new BatchFixtureResult(parts[0], ok, outputValue, errorValue);
            }
        }

        foreach (string fixture in fixtures)
        {
            Stopwatch fixtureClock = Stopwatch.StartNew();
            batchByFixture.TryGetValue(fixture, out BatchFixtureResult? entry);
            string? branchOutput = entry is { ok: true } ? entry.output : null;
            WindowsRemediationStateProbe branchProbe = new((_, _) => Task.FromResult(branchOutput), incident);
            RemediationVerificationObservation observation = await branchProbe.ObserveAsync(firewall, default);
            long elapsedMs = fixtureClock.ElapsedMilliseconds;
            // 关闭或缺少某项防火墙配置文件时（常见于第三方安全软件接管环境），精确的阻断规则本身存在且有效即返回 Verified。
            RemediationVerificationStatus expected = fixture is "exact" or "prefix-neighbor" or
                "profile-disabled" or "profile-missing" or "profile-error"
                ? RemediationVerificationStatus.Verified : fixture is "duplicate" or "provider-error"
                    ? RemediationVerificationStatus.Unknown : RemediationVerificationStatus.ResidualDetected;
            bool branchValid = entry is not null && fixture switch
            {
                "exact" => coldExactObservation.Status == RemediationVerificationStatus.Verified && entry.ok && string.Equals(entry.output, "Verified", StringComparison.Ordinal),
                "duplicate" => entry.ok && string.Equals(entry.output, "Unknown", StringComparison.Ordinal),
                "provider-error" => !entry.ok && entry.output is null && (entry.error?.Contains("Inert provider failure", StringComparison.Ordinal) ?? false),
                _ => entry.ok
            };
            if (observation.Status == RemediationVerificationStatus.Unknown || observation.Status != expected || !branchValid)
                Console.WriteLine("FW_PREDICATE " + JsonSerializer.Serialize(new
                {
                    Fixture = fixture,
                    ElapsedMs = elapsedMs,
                    status = observation.Status.ToString(),
                    expected = expected.ToString(),
                    observation.Message,
                    returnedNull = branchOutput is null,
                    Output = branchOutput,
                    coldExactStatus = fixture == "exact" ? coldExactObservation.Status.ToString() : null,
                    coldExactOutput = fixture == "exact" ? coldExactOutput : null,
                    trace = fixture == "exact" ? ReadFixtureTrace(coldExactTrace) : entry?.error ?? "batch-isolated-scope"
                }));
            Check("防火墙真实只读谓词对象回归 " + fixture, observation.Status == expected && branchValid);
        }

        await slowPass1Waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        slowClock.Advance(TimeSpan.FromMilliseconds(11500));
        await slowPass2Waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        slowClock.Advance(TimeSpan.FromMilliseconds(11500));
        RemediationRunResult slowResult = await slow;
        Check("防火墙大于10秒的两轮观察通过并放行依赖隔离", slowResult.Actions.Count == 2 && slowResult.Actions.All(a => a.Success) &&
            slowResult.Actions[0].Verifications.Count == 2 && slowResult.Actions[0].Verifications.All(v => v.Status == RemediationVerificationStatus.Verified));

        await timeoutWaiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        timeoutVirtualClock.Advance(TimeSpan.FromMilliseconds(14900));
        bool timedOutPendingBefore15s = !timedOut.IsCompleted;
        timeoutVirtualClock.Advance(TimeSpan.FromMilliseconds(100));
        RemediationRunResult timeoutResult = await timedOut;
        Check("防火墙15秒上限到达保持Unknown且依赖不执行", timedOutPendingBefore15s &&
            timeoutResult.Actions[0].VerificationStatus == RemediationVerificationStatus.Unknown &&
            timeoutResult.Actions[1].ExecutionStatus == RemediationExecutionStatus.SkippedDependency && timeoutClock.Elapsed < TimeSpan.FromSeconds(25));

        await ordinaryWaiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        ordinaryClock.Advance(TimeSpan.FromMilliseconds(9999));
        bool ordinaryPendingBefore10s = !ordinaryProbe.IsCompleted;
        ordinaryClock.Advance(TimeSpan.FromMilliseconds(1));
        await ordinaryProbe;
        Check("防火墙专属预算不延长普通动作", ordinaryPendingBefore10s && ordinary.VerificationStatus == RemediationVerificationStatus.Unknown);

        CaseVerificationEpisode episode = await caseProbe;
        Check("防火墙跨会话复验与真实脚本runner均允许超过4秒", episode.Targets.Single().Status == RemediationVerificationStatus.Verified &&
            episode.State == CaseReverificationState.SelectedTargetsVerified &&
            CaseReadOnlyScriptRunner.DefaultTimeout == TimeSpan.FromSeconds(15) &&
            CaseReadOnlyScriptRunner.DefaultTimeout == RemediationVerification.FirewallProbeTimeout &&
            slowCaseRunnerElapsedMs >= 350);

        static string TraceStage(string path, string stage) =>
            "[IO.File]::AppendAllText([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(path)) + "')),('" + stage +
            " '+[DateTime]::UtcNow.ToString('O')+[Environment]::NewLine));";

        static string ReadFixtureTrace(string path)
        {
            try { return File.Exists(path) ? File.ReadAllText(path) : "not-created"; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "trace-read-error:" + ex.GetType().Name; }
        }

        async Task<RemediationRunResult> TimeoutSequenceAsync(ManualTimeProvider clock, TaskCompletionSource waiting)
        {
            try
            {
                return await SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
                {
                    Task wait = Task.Delay(Timeout.InfiniteTimeSpan, clock, token);
                    waiting.TrySetResult();
                    await wait;
                    return new() { Status = RemediationVerificationStatus.Verified };
                }), timeProvider: clock);
            }
            finally { timeoutClock.Stop(); }
        }

        async Task<RemediationRunResult> SequenceAsync(IRemediationStateProbe firewallProbe, bool complete = false,
            CancellationToken token = default, TimeProvider? timeProvider = null)
        {
            RemediationPlan plan = new() { Actions = [firewall, cleanup] };
            RemediationRunResult result = new() { PlanId = plan.PlanId };
            RemediationVerification verification = new(new FirewallBudgetProbe((action, bounded) => action == firewall
                ? firewallProbe.ObserveAsync(action, bounded)
                : Task.FromResult(new RemediationVerificationObservation { Status = RemediationVerificationStatus.NoResidual })),
                timeProvider);
            try
            {
                await BrokerActionSequencer.RunAsync(plan, result, new Dictionary<Guid, string>(),
                    (_, _) => Task.FromResult("Inert simulated action; no system change."),
                    (action, outcome, bounded) => verification.ObserveAsync(action, outcome, 1, bounded),
                    _ => Task.CompletedTask, token: token);
                if (complete) await verification.CompleteAsync(plan, result, token, TimeSpan.Zero);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            return result;
        }

        async Task<CaseVerificationEpisode> SlowCaseAsync()
        {
            Stopwatch caseClock = Stopwatch.StartNew();
            const string sid = "S-1-5-21-123-456-789-1001";
            DateTimeOffset epoch = DateTimeOffset.UtcNow.AddHours(-3);
            CaseSessionObservation Session(bool current) => new()
            {
                UserSid = sid,
                MachineName = "INERT-FIREWALL-FIXTURE",
                CapturedAtUtc = current ? epoch.AddHours(2) : epoch,
                IdentityStatus = DiagnosticReadStatus.Complete,
                BootStatus = DiagnosticReadStatus.Complete,
                BootIdentity = current ? "boot-B" : "boot-A",
                BootEventRecordId = current ? 200 : 100,
                BootStartedAtUtc = current ? epoch.AddHours(1) : epoch.AddHours(-1),
                LogonStatus = DiagnosticReadStatus.Complete,
                InteractiveLogonId = current ? "logon-B" : "logon-A",
                InteractiveLogonStartedAtUtc = current ? epoch.AddHours(1).AddMinutes(1) : epoch.AddMinutes(-50),
                LogonType = 2,
                SessionId = 1
            };
            RemediationPlan plan = new() { RequestedBySid = sid, CreatedAtUtc = epoch, ExpiresAtUtc = epoch.AddMinutes(15), Actions = [firewall] };
            RemediationRunResult result = new()
            {
                PlanId = plan.PlanId,
                Success = true,
                Disposition = RemediationRunDisposition.Completed,
                StartedAtUtc = epoch.AddSeconds(1),
                CompletedAtUtc = epoch.AddMinutes(1),
                Actions = [new()
                {
                    ActionId = firewall.ActionId, Type = firewall.Type, Target = firewall.Target, Success = true,
                    ExecutionStatus = RemediationExecutionStatus.Succeeded, VerificationStatus = RemediationVerificationStatus.Verified
                }]
            };
            RemediationCaseRecord record = new()
            {
                UserSid = sid,
                CreatedAtUtc = epoch,
                UpdatedAtUtc = epoch,
                BaselineSession = Session(false),
                Plans = [plan],
                ExecutionResults = [result],
                RequireContentFollowUp = false,
                RequireRelatedFollowUp = false
            };
            WindowsRemediationStateProbe probe = new((_, token) => RunCaseFixtureScriptAsync(token), result.IncidentId);
            CaseVerificationEpisode observed = await new RemediationCaseReverification(probe, new Phase3CaseSessions(Session(true))).RecheckAsync(record);
            Console.WriteLine("FW_CASE_EPISODE " + JsonSerializer.Serialize(new
            {
                elapsedMs = caseClock.ElapsedMilliseconds,
                state = observed.State.ToString(),
                transition = observed.Transition.ToString(),
                observed.SelectedActionCount,
                targets = observed.Targets.Select(target => new { status = target.Status.ToString(), target.ExecutionSucceeded, target.Message }),
                requiredChecks = observed.Checks.Where(check => check.Required)
                    .Select(check => new { check.Name, status = check.Status.ToString(), check.Detail })
            }));
            return observed;

            async Task<string?> RunCaseFixtureScriptAsync(CancellationToken token)
            {
                Stopwatch runnerClock = Stopwatch.StartNew();
                string tracePath = Path.Combine(traceRoot, "slow-case-" + Guid.NewGuid().ToString("N") + ".log");
                string? output = null;
                string? exception = null;
                try
                {
                    output = await CaseReadOnlyScriptRunner.RunAsync(
                        TraceStage(tracePath, "entry") + "try{" + TraceStage(tracePath, "beforeSleep") +
                        "[System.Threading.Thread]::Sleep(400);" + TraceStage(tracePath, "afterSleep") +
                        "'Verified'}catch{'FixtureError:'+($_.Exception.GetType().FullName)+':'+$_.Exception.Message}finally{" +
                        TraceStage(tracePath, "end") + "}", token);
                    return output;
                }
                catch (Exception ex)
                {
                    exception = ex.GetType().FullName;
                    throw;
                }
                finally
                {
                    slowCaseRunnerElapsedMs = runnerClock.ElapsedMilliseconds;
                    Console.WriteLine("FW_CASE_RUNNER " + JsonSerializer.Serialize(new
                    {
                        elapsedMs = slowCaseRunnerElapsedMs,
                        returnedNull = output is null,
                        output,
                        exception,
                        callerCancelled = token.IsCancellationRequested,
                        trace = ReadFixtureTrace(tracePath)
                    }));
                }
            }
        }
    }

    private sealed record BatchFixtureResult(string fixture, bool ok, string? output, string? error);

    private sealed class FirewallBudgetProbe(Func<RemediationAction, CancellationToken, Task<RemediationVerificationObservation>> observe) : IRemediationStateProbe
    {
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken token) => observe(action, token);
    }

    private static string FirewallObjectFixture(string fixture, string ruleName, string target) =>
        $"$fixture='{fixture}';\n" + FirewallObjectFixtureBody(ruleName, target);

    private static string FirewallObjectFixtureBody(string ruleName, string target) => $$$$"""
        $expectedName=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{Convert.ToBase64String(Encoding.UTF8.GetBytes(ruleName))}}}}'));
        $expectedTarget=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{Convert.ToBase64String(Encoding.UTF8.GetBytes(target))}}}}'));
        function Get-NetFirewallRule {
            [CmdletBinding()]param([string]$PolicyStore,[string]$DisplayName)
            if($PolicyStore -cne 'ActiveStore' -or $DisplayName -cne ($expectedName+'*')){throw 'Expected bounded provider query'}
            if($fixture -eq 'provider-error'){throw 'Inert provider failure'}
            if($fixture -eq 'missing'){return}
            $rule=[pscustomobject]@{DisplayName=$expectedName;Enabled='True';Action='Block';Direction='Outbound';Profile='Any'}
            switch($fixture){
                'disabled'{$rule.Enabled='False'} 'allow'{$rule.Action='Allow'} 'inbound'{$rule.Direction='Inbound'}
                'limited-profile'{$rule.Profile='Private'} 'prefix-only'{$rule.DisplayName+='-neighbor'}
                'case-only'{$rule.DisplayName=$expectedName.ToUpperInvariant()}
            }
            $rule
            if($fixture -eq 'duplicate'){$rule}
            if($fixture -eq 'prefix-neighbor'){[pscustomobject]@{DisplayName=($expectedName+'-neighbor')}}
        }
        function Get-NetFirewallApplicationFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{Program=$(if($fixture -eq 'program'){'C:\other.exe'}else{$expectedTarget})} }
        }
        function Get-NetFirewallPortFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{Protocol=$(if($fixture -eq 'protocol'){'TCP'}else{'Any'});LocalPort='Any';RemotePort=$(if($fixture -eq 'port'){'443'}else{'Any'})} }
        }
        function Get-NetFirewallAddressFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{LocalAddress='Any';RemoteAddress=$(if($fixture -eq 'address'){'192.0.2.1'}else{'Any'})} }
        }
        function Get-NetFirewallServiceFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{Service=$(if($fixture -eq 'service'){'InertService'}else{'Any'})} }
        }
        function Get-NetFirewallInterfaceFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{InterfaceAlias=$(if($fixture -eq 'interface'){'Ethernet'}else{'Any'})} }
        }
        function Get-NetFirewallInterfaceTypeFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { [pscustomobject]@{InterfaceType=$(if($fixture -eq 'interface-type'){'Wireless'}else{'Any'})} }
        }
        function Get-NetFirewallProfile {
            [CmdletBinding()]param([string]$PolicyStore)
            if($PolicyStore -cne 'ActiveStore' -or $fixture -eq 'profile-error'){throw 'Inert profile failure'}
            $count=if($fixture -eq 'profile-missing'){2}else{3}
            for($j=0;$j -lt $count;$j++){[pscustomobject]@{Enabled=$(if($fixture -eq 'profile-disabled' -and $j -eq 0){2}else{1})}}
        }

        """;
}
