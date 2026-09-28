using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV030RelatedMessageFlows()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        const string target = @"C:\Users\Fixture\App\tool.exe";
        Phase2SourceFixture fixture = new(sid);
        fixture.Sources.Add(new()
        {
            Kind = "Run",
            Scope = "CurrentUser",
            UserSid = sid,
            Location = "inert/Run",
            RawCommand = '"' + target + '"',
            DetailText = MessageText.Create("Backend.Core.RelatedComponentDiscovery.ReadRun.02")
        });
        RelatedComponentDiagnosticReport diagnostic = new() { TargetUserSid = sid };
        new RelatedComponentDiscovery(fixture).Collect(new() { TargetUserSid = sid }, diagnostic, new());
        ScanReport report = new() { RelatedComponentDiagnostics = diagnostic };
        string saved = JsonSerializer.Serialize(report, JsonFile.Options);
        List<ReportBatch> frames = []; new ReportBatchWriter(frames.Add).Send(report, true);
        ReportBatchReader reader = new();
        foreach (ReportBatch frame in frames) reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(frame, JsonFile.Options), JsonFile.Options)!);
        var received = reader.Report!.RelatedComponentDiagnostics!;
        using (DisplayText.UseCulture(DisplayText.English))
        {
            Check("后台消息 关联发现经过分片后显示英语并保留来源命令", received.Candidates.Count == 1 && received.Sources[0].RawCommand == '"' + target + '"' &&
                !V030HasHan(RelatedComponentReportPresentation.Describe(received)) && received.Candidates[0].ContentStatus == DiagnosticReadStatus.NotChecked);
            Check("后台消息 关联显示不改变JSON或处置资格", saved == JsonSerializer.Serialize(report, JsonFile.Options) && report.Findings.Count == 0);
            RelatedCommandResolution command = RelatedCommandResolver.Resolve(new("powershell.exe -Command $unknown"));
            Check("后台消息 命令解析说明保留英语与有界目标", command.NoteMessages?.Count > 0 && command.NoteTexts.All(text => !V030HasHan(text.Display)) && command.Targets.Count == 0);
        }
        RelatedComponentDiagnosticReport malformed = new()
        {
            TargetUserSid = sid,
            Sources = [new() { Kind = "Run", Scope = "CurrentUser", UserSid = sid,
            DetailMessage = new("bad id", []) }]
        };
        Check("后台消息 关联描述在分片发送前拒绝", V020Throws<InvalidDataException>(() => RelatedComponentFragments.Create(malformed)));
        TrustProxyDiagnosticReport malformedProxy = new() { TargetUserSid = sid, Checks = [new() { Name = "inert", DetailMessage = new("bad id", []) }] };
        Check("后台消息 诊断描述在分片发送前拒绝", V020Throws<InvalidDataException>(() => TrustProxyDiagnosticFragments.Create(malformedProxy)));
        Check("后台消息 缺失复验集合按无效结果处理", V020Throws<InvalidDataException>(() => ProtectedRemediationResultReader.Validate(new(), new()
        { Actions = [new() { Verifications = null! }] })));
        Check("后台消息 空动作按无效结果处理", V020Throws<InvalidDataException>(() => ProtectedRemediationResultReader.Validate(new(), new() { Actions = [null!] })));
    }
}
