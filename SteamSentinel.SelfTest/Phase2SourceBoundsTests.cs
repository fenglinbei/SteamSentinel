using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestPhase2SourceBounds()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        const string app = @"C:\Users\Fixture\App";
        Phase2SourceFixture fixture = new(sid);
        string[] scripts = Enumerable.Range(0, 8).Select(i => app + "\\script" + i + ".ps1").ToArray();
        string command = "cmd.exe /c " + string.Join(" & ", scripts.Select(path => "\"" + path + "\""));
        fixture.Sources.Add(new() { Kind = "Run", Scope = "CurrentUser", UserSid = sid, Location = "Run/many-scripts", RawCommand = command });
        for (int script = 0; script < scripts.Length; script++)
            fixture.Files[scripts[script]] = new(DiagnosticReadStatus.Complete, "harmless fixture",
                Encoding.UTF8.GetBytes(string.Join("\r\n", Enumerable.Range(0, 32).Select(i => "rundll32 \"" + app + "\\module" + script + "_" + i + ".dll\",Entry"))));
        RelatedComponentDiagnosticReport discovery = new() { TargetUserSid = sid };
        new RelatedComponentDiscovery(fixture).Collect(new() { TargetUserSid = sid }, discovery, new());
        RelatedSourceObservation source = discovery.Sources.Single();
        Check("第二批 多脚本累计来源目标最多128项", fixture.FileRequests.Count >= 4 && source.ResolvedTargets.Count == 128);
        Check("第二批 来源目标截断保留原始命令和明确缺口", source.RawCommand == command && source.Status == DiagnosticReadStatus.LimitReached &&
            source.Detail.Contains(RelatedComponentRecordBounds.SourceTargetLimitDetail) && discovery.Checks.Any(c => c.Name == "来源目标列表限额" && c.ObservationId == source.Id && c.Status == DiagnosticReadStatus.LimitReached));
        ReportBatchReader reader = new();
        new ReportBatchWriter(reader.Apply).Send(new() { RelatedComponentDiagnostics = discovery }, final: true);
        Check("第二批 多脚本极端来源完整通过有界IPC", reader.Report!.RelatedComponentDiagnostics!.Sources.Single().ResolvedTargets.Count == 128 && !reader.HasIncompleteRelatedComponentDiagnostics);

        RelatedSourceObservation longSource = new()
        {
            Id = "long-source",
            Kind = "Run",
            Scope = "LocalMachine",
            Location = new string('L', 8000),
            WorkingDirectory = new string('W', 8000),
            RawCommand = new string('R', 32768),
            Detail = "original detail"
        };
        string raw = longSource.RawCommand;
        string[] longPaths = Enumerable.Range(0, 128).Select(i => "C:\\" + new string('x', 1024) + i + ".dll").ToArray();
        bool omitted = RelatedComponentRecordBounds.MergeTargets(longSource, longPaths);
        Check("第二批 来源目标字符预算为原始字段和详情预留空间", omitted && longSource.ResolvedTargets.Count is > 0 and < 128 && longSource.RawCommand == raw && longSource.Status == DiagnosticReadStatus.LimitReached);
        longSource.Detail = new string('d', RelatedComponentRecordBounds.MaximumDetailCharacters);
        RelatedComponentDiagnosticReport longDiagnostic = new() { Sources = [longSource] };
        ReportBatchReader longReader = new();
        new ReportBatchWriter(longReader.Apply).Send(new() { RelatedComponentDiagnostics = longDiagnostic }, final: true);
        Check("第二批 字段加派生路径及完整详情仍满足单记录传输预算", longReader.Report!.RelatedComponentDiagnostics!.Sources.Single().RawCommand == raw);

        RelatedSourceObservation merged = new() { Id = "merged", Kind = "Run", Scope = "LocalMachine", RawCommand = "original exact command" };
        RelatedComponentRecordBounds.MergeTargets(merged, Enumerable.Range(0, 100).Select(i => @"C:\Fixture\" + i + ".dll"));
        bool mergedOmitted = RelatedComponentRecordBounds.MergeTargets(merged, Enumerable.Range(50, 100).Select(i => @"C:\Fixture\" + i + ".dll"));
        Check("第二批 跨轮来源合并去重且继续遵守128项上限", mergedOmitted && merged.ResolvedTargets.Count == 128 && merged.ResolvedTargets.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 128 && merged.RawCommand == "original exact command");
        JsonSerializerOptions options = new(JsonFile.Options) { WriteIndented = false };
        string snapshot = JsonSerializer.Serialize(merged, options);
        Check("第二批 重复引用在满额时仍可保持原记录", RelatedComponentRecordBounds.TryAddTarget(merged, merged.ResolvedTargets[0].ToUpperInvariant()) && snapshot == JsonSerializer.Serialize(merged, options));

        Phase2SourceFixture oversized = new(sid);
        string oversizedTaskCommand = "\"C:\\" + new string('e', 31980) + ".exe\" " + new string('a', 32760);
        oversized.Sources.Add(new()
        {
            Kind = "Task",
            Scope = "CurrentUser",
            UserSid = sid,
            Location = "Tasks/oversized#Exec1",
            RawCommand = oversizedTaskCommand,
            ExecutablePath = app + @"\would-run.exe",
            Arguments = new string('a', 32760),
            WorkingDirectory = "C:\\" + new string('w', 32760),
            Detail = new string('d', 4096)
        });
        RelatedComponentDiagnosticReport oversizedReport = new() { TargetUserSid = sid };
        new RelatedComponentDiscovery(oversized).Collect(new() { TargetUserSid = sid }, oversizedReport, new());
        RelatedSourceObservation omittedSource = oversizedReport.Sources.Single();
        Check("第二批 Task各字段未超单字段限额但组合超限时整条原命令不纳入", oversizedTaskCommand.Length <= 65536 &&
            omittedSource.RawCommand == "" && omittedSource.WorkingDirectory is null && omittedSource.Kind == "Task" && omittedSource.Location == "Tasks/oversized#Exec1");
        Check("第二批 超大原始来源显式未解析且不生成候选", omittedSource.Status == DiagnosticReadStatus.LimitReached &&
            omittedSource.Detail.Contains("原始来源超过记录限额，未完整纳入/未解析") && omittedSource.ResolvedTargets.Count == 0 &&
            oversizedReport.Candidates.Count == 0 && oversized.FileRequests.Count == 0 && oversizedReport.Checks.Any(c => c.Name == "原始来源记录限额" && c.ObservationId == omittedSource.Id));

        RelatedSourceRead ordinary = new()
        {
            Kind = "Run",
            Scope = "CurrentUser",
            UserSid = sid,
            Location = "Run/oversized-fields",
            RawCommand = "powershell.exe -File \"" + scripts[0] + "\"",
            ExecutablePath = scripts[0]
        };
        Phase2SourceFixture fields = new(sid);
        fields.Sources.AddRange([ordinary with { RawCommand = new string('r', 65537) }, ordinary with { Kind = new string('k', 129) },
            ordinary with { Scope = new string('s', 129) }, ordinary with { Location = new string('l', 32769) },
            ordinary with { WorkingDirectory = new string('w', 32769) }, ordinary with { Detail = new string('d', 8193) },
            ordinary with { UserSid = new string('u', 513) }]);
        fields.Files[scripts[0]] = new(DiagnosticReadStatus.Complete, "must never be parsed", Encoding.UTF8.GetBytes("rundll32 C:\\Fixture\\must-not-appear.dll,Entry"));
        RelatedComponentDiagnosticReport fieldsReport = new() { TargetUserSid = sid };
        new RelatedComponentDiscovery(fields).Collect(new() { TargetUserSid = sid }, fieldsReport, new());
        Check("第二批 任一来源字段超限均保留有界标识并跳过解析", fieldsReport.Sources.Count == 7 &&
            fieldsReport.Sources.All(s => s.Status == DiagnosticReadStatus.LimitReached && s.RawCommand.Length == 0 && s.ResolvedTargets.Count == 0) &&
            fieldsReport.Candidates.Count == 0 && fields.FileRequests.Count == 0);
        int largestWire = 0;
        foreach (RelatedComponentDiagnosticReport diagnostic in new[] { oversizedReport, fieldsReport })
        {
            ReportBatchReader boundedReader = new();
            new ReportBatchWriter(batch =>
            {
                string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, options);
                largestWire = Math.Max(largestWire, wire.Length);
                boundedReader.Apply(JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!);
            }).Send(new() { RelatedComponentDiagnostics = diagnostic }, final: true);
            Check("第二批 超大原始来源以明确未读状态完整IPC往返 " + diagnostic.Sources.Count, !boundedReader.HasIncompleteRelatedComponentDiagnostics &&
                boundedReader.Report!.RelatedComponentDiagnostics!.Sources.Count == diagnostic.Sources.Count &&
                boundedReader.Report.RelatedComponentDiagnostics.Sources.All(s => s.RawCommand == "" && s.Status == DiagnosticReadStatus.LimitReached));
        }
        Check("第二批 超大来源降为有界未读标识后通信帧仍小于一MiB", largestWire < 1024 * 1024);

        RelatedSourceObservation noteCapacity = new()
        {
            Id = "notes",
            Kind = "Run",
            Scope = "LocalMachine",
            RawCommand = "preserved",
            Detail = new string('d', RelatedComponentRecordBounds.MaximumDetailCharacters)
        };
        Check("第二批 后续解析说明不能把已验证来源推过字段预算", !RelatedComponentRecordBounds.TryAppendDetail(noteCapacity, "additional detail") &&
            noteCapacity.Detail.Length <= RelatedComponentRecordBounds.MaximumDetailCharacters && noteCapacity.RawCommand == "preserved" && noteCapacity.Status == DiagnosticReadStatus.LimitReached);
    }
}
