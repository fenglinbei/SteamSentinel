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

        // Start independent deadline regressions together so the 15-second ceiling is
        // tested without adding the individual waiting periods to the full suite.
        Task<RemediationRunResult> slow = SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(11500), token);
            return new() { Status = RemediationVerificationStatus.Verified };
        }), complete: true);
        Stopwatch timeoutClock = Stopwatch.StartNew();
        Task<RemediationRunResult> timedOut = TimeoutSequenceAsync();
        RemediationActionResult ordinary = new() { ExecutionStatus = RemediationExecutionStatus.Succeeded };
        Task ordinaryProbe = new RemediationVerification(new FirewallBudgetProbe(async (_, token) =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(11500), token);
            return new() { Status = RemediationVerificationStatus.Verified };
        })).ObserveAsync(cleanup, ordinary, 1);
        long slowCaseRunnerElapsedMs = 0;

        using (CancellationTokenSource cancelled = new(TimeSpan.FromMilliseconds(100)))
        {
            RemediationRunResult cancellation = await SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return new() { Status = RemediationVerificationStatus.Verified };
            }), token: cancelled.Token);
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

        // Each fixture invokes the unchanged generated script in a fresh trusted system
        // PowerShell process. All eight Get-NetFirewall commands are shadowed functions.
        string[] fixtures = ["exact", "prefix-neighbor", "missing", "prefix-only", "case-only", "duplicate", "disabled",
            "allow", "inbound", "limited-profile", "program", "protocol", "port", "address", "service", "interface",
            "interface-type", "profile-disabled", "profile-missing", "profile-error", "provider-error"];
        // Serialize real process starts; the independent deadline mocks above remain
        // concurrent. The first predicate still runs without a warm-up or retry.
        using SemaphoreSlim fixtureGate = new(1);
        var fixtureResults = await Task.WhenAll(fixtures.Select(async fixture =>
        {
            await fixtureGate.WaitAsync();
            try
            {
                Stopwatch fixtureClock = Stopwatch.StartNew();
                string tracePath = Path.Combine(traceRoot, fixture + "-" + Guid.NewGuid().ToString("N") + ".log");
                string? runnerOutput = null;
                string fixtureScript = FirewallObjectFixture(fixture, $"SteamSentinel-{incident:N}-{firewall.ActionId:N}", firewall.Target);
                WindowsRemediationStateProbe probe = new(async (value, token) =>
                {
                    runnerOutput = await CaseReadOnlyScriptRunner.RunAsync(TraceStage(tracePath, "entry") + "try{" +
                        fixtureScript + value + "}finally{" + TraceStage(tracePath, "end") + "}", token);
                    return runnerOutput;
                }, incident);
                RemediationVerificationObservation observation = await probe.ObserveAsync(firewall, default);
                return (Fixture: fixture, Observation: observation, ElapsedMs: fixtureClock.ElapsedMilliseconds, TracePath: tracePath, Output: runnerOutput);
            }
            finally { fixtureGate.Release(); }
        }));
        foreach (var fixture in fixtureResults)
        {
            // 关闭或缺少某项防火墙配置文件时（常见于第三方安全软件接管环境），精确的阻断规则本身存在且有效即返回 Verified。
            RemediationVerificationStatus expected = fixture.Fixture is "exact" or "prefix-neighbor" or
                "profile-disabled" or "profile-missing" or "profile-error"
                ? RemediationVerificationStatus.Verified : fixture.Fixture is "duplicate" or "provider-error"
                    ? RemediationVerificationStatus.Unknown : RemediationVerificationStatus.ResidualDetected;
            if (fixture.Observation.Status == RemediationVerificationStatus.Unknown || fixture.Observation.Status != expected)
                Console.WriteLine("FW_PREDICATE " + JsonSerializer.Serialize(new
                {
                    fixture.Fixture,
                    fixture.ElapsedMs,
                    status = fixture.Observation.Status.ToString(),
                    expected = expected.ToString(),
                    fixture.Observation.Message,
                    returnedNull = fixture.Output is null,
                    fixture.Output,
                    trace = ReadFixtureTrace(fixture.TracePath)
                }));
            Check("防火墙真实只读谓词对象回归 " + fixture.Fixture, fixture.Observation.Status == expected);
        }

        Task<CaseVerificationEpisode> caseProbe = SlowCaseAsync();
        RemediationRunResult slowResult = await slow;
        Check("防火墙大于10秒的两轮观察通过并放行依赖隔离", slowResult.Actions.Count == 2 && slowResult.Actions.All(a => a.Success) &&
            slowResult.Actions[0].Verifications.Count == 2 && slowResult.Actions[0].Verifications.All(v => v.Status == RemediationVerificationStatus.Verified));
        RemediationRunResult timeoutResult = await timedOut;
        Check("防火墙15秒上限到达保持Unknown且依赖不执行", timeoutResult.Actions[0].VerificationStatus == RemediationVerificationStatus.Unknown &&
            timeoutResult.Actions[1].ExecutionStatus == RemediationExecutionStatus.SkippedDependency && timeoutClock.Elapsed < TimeSpan.FromSeconds(25));
        await ordinaryProbe;
        Check("防火墙专属预算不延长普通动作", ordinary.VerificationStatus == RemediationVerificationStatus.Unknown);
        CaseVerificationEpisode episode = await caseProbe;
        Check("防火墙跨会话复验与真实脚本runner均允许超过4秒", episode.Targets.Single().Status == RemediationVerificationStatus.Verified &&
            episode.State == CaseReverificationState.SelectedTargetsVerified && slowCaseRunnerElapsedMs >= 4500);

        static string TraceStage(string path, string stage) =>
            "[IO.File]::AppendAllText([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(path)) + "')),('" + stage +
            " '+[DateTime]::UtcNow.ToString('O')+[Environment]::NewLine));";

        static string ReadFixtureTrace(string path)
        {
            try { return File.Exists(path) ? File.ReadAllText(path) : "not-created"; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "trace-read-error:" + ex.GetType().Name; }
        }

        async Task<RemediationRunResult> TimeoutSequenceAsync()
        {
            try
            {
                return await SequenceAsync(new FirewallBudgetProbe(async (_, token) =>
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    return new() { Status = RemediationVerificationStatus.Verified };
                }));
            }
            finally { timeoutClock.Stop(); }
        }

        async Task<RemediationRunResult> SequenceAsync(IRemediationStateProbe firewallProbe, bool complete = false, CancellationToken token = default)
        {
            RemediationPlan plan = new() { Actions = [firewall, cleanup] };
            RemediationRunResult result = new() { PlanId = plan.PlanId };
            RemediationVerification verification = new(new FirewallBudgetProbe((action, bounded) => action == firewall
                ? firewallProbe.ObserveAsync(action, bounded)
                : Task.FromResult(new RemediationVerificationObservation { Status = RemediationVerificationStatus.NoResidual })));
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
                        "[System.Threading.Thread]::Sleep(4500);" + TraceStage(tracePath, "afterSleep") +
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

    private sealed class FirewallBudgetProbe(Func<RemediationAction, CancellationToken, Task<RemediationVerificationObservation>> observe) : IRemediationStateProbe
    {
        public Task<RemediationVerificationObservation> ObserveAsync(RemediationAction action, CancellationToken token) => observe(action, token);
    }

    private static string FirewallObjectFixture(string fixture, string ruleName, string target) => $$$$"""
        $fixture='{{{{fixture}}}}';
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
