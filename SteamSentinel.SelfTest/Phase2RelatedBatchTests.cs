using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestPhase2RelatedBatch()
    {
        JsonSerializerOptions options = new(JsonFile.Options) { WriteIndented = false };
        ScanReport source = RelatedBatchFixture();
        source.TrustProxyDiagnostics = TrustProxyBatchFixture(1, [1, 2, 3]).TrustProxyDiagnostics;
        List<ReportBatch> frames = [];
        ReportBatchReader reader = new();
        int largest = 0;
        ReportBatchWriter writer = new(batch =>
        {
            string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, options);
            largest = Math.Max(largest, wire.Length);
            ReportBatch restored = JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!;
            frames.Add(restored); reader.Apply(restored);
        });
        writer.Send(source);
        Check("组件关联快照只在 final 传输", frames.All(f => f.RelatedComponentFragment is null) && reader.Report!.RelatedComponentDiagnostics is null);
        writer.Send(source, final: true);
        Check("组件关联诊断所有记录与限额完整往返", JsonSerializer.Serialize(source.RelatedComponentDiagnostics, options) == JsonSerializer.Serialize(reader.Report!.RelatedComponentDiagnostics, options));
        Check("组件和代理证书两种分片保持独立完整", !reader.HasIncompleteRelatedComponentDiagnostics && !reader.HasIncompleteTrustProxyDiagnostics &&
            JsonSerializer.Serialize(source.TrustProxyDiagnostics, options) == JsonSerializer.Serialize(reader.Report!.TrustProxyDiagnostics, options));
        Check("组件分片保留普通批次序号范围和最终完成时间", reader.Count == writer.Count && reader.Report!.CompletedAtUtc == source.CompletedAtUtc &&
            reader.Report.Findings.Single().Id == source.Findings.Single().Id && reader.Report.CoverageNotes.SequenceEqual(source.CoverageNotes));
        Check("组件分片不把完整诊断塞入 Data 且通信帧小于一 MiB", frames.All(f => f.Data.RelatedComponentDiagnostics is null) && largest < 1024 * 1024);
        Check("组件观察传输不引入处置资格", reader.Report!.Findings.All(f => !f.CanRemediate && !f.IsKnownMalware));

        int first = frames.FindIndex(f => f.RelatedComponentFragment is not null);
        int host = frames.FindIndex(f => f.RelatedComponentFragment?.Host is not null);
        int candidate = frames.FindIndex(f => f.RelatedComponentFragment?.Candidate is not null);
        int relation = frames.FindIndex(f => f.RelatedComponentFragment?.Relation is not null);
        int round = frames.FindIndex(f => f.RelatedComponentFragment?.Round is not null);
        ReportBatchReader interrupted = new();
        foreach (ReportBatch frame in frames.Take(first + 1)) interrupted.Apply(frame);
        Check("组件分片丢失尾部时报告保持未完成", interrupted.HasIncompleteRelatedComponentDiagnostics && interrupted.Report is
        { CompletedAtUtc: null, Coverage: ScanCoverage.Partial, RelatedComponentDiagnostics.CompletedAtUtc: null });
        Check("代理证书结束片不提前宣布待传组件诊断完成", frames.Where(f => f.TrustProxyFragment?.IsFinal == true).All(f => f.Data.CompletedAtUtc is null));

        bool RejectAt(int index, Func<ReportBatch, ReportBatch> modify)
        {
            ReportBatchReader target = new();
            foreach (ReportBatch frame in frames.Take(index)) target.Apply(frame);
            string before = JsonSerializer.Serialize(target.Report, options);
            int count = target.Count;
            ReportBatch altered = modify(frames[index]);
            altered = altered with
            {
                Data = new ScanReport
                {
                    ScanId = source.ScanId,
                    Findings = [new() { Id = "MUST-NOT-COMMIT", Title = "rejected" }],
                    RelatedComponentDiagnostics = altered.Data.RelatedComponentDiagnostics
                }
            };
            try { target.Apply(altered); }
            catch (InvalidDataException) { return count == target.Count && JsonSerializer.Serialize(target.Report, options) == before; }
            return false;
        }
        Check("组件错误偏移拒绝且普通发现不部分提交", RejectAt(candidate, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { Offsets = b.RelatedComponentFragment.Offsets with { Candidates = 1 } } }));
        Check("组件元数据 SID 变化拒绝且不部分提交", RejectAt(host, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { Metadata = b.RelatedComponentFragment.Metadata with { TargetUserSid = "S-1-5-21-1-2-3-1002" } } }));
        Check("组件跨片限额变化被拒绝", RejectAt(host, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Metadata = b.RelatedComponentFragment.Metadata with
                { AppliedLimits = b.RelatedComponentFragment.Metadata.AppliedLimits! with { MaximumTotalBytes = 1 } }
            }
        }));
        Check("组件当前用户来源须与目标 SID 一致", RejectAt(first, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { Metadata = b.RelatedComponentFragment.Metadata with { TargetUserSid = "S-1-5-21-1-2-3-1002" } } }));
        Check("组件单片不能混装两条观察", RejectAt(host, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { Source = source.RelatedComponentDiagnostics!.Sources[0] } }));
        Check("组件提前结束标记被拒绝", RejectAt(first, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { IsFinal = true } }));
        Check("组件最后一片缺少结束标记被拒绝", RejectAt(round, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { IsFinal = false } }));
        Check("组件候选不能把宿主 ID 充当来源 ID", RejectAt(candidate, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Candidate = new()
                { Id = "candidate", Path = @"C:\Fixture\module.dll", SourceObservationIds = ["host"] }
            }
        }));
        Check("组件宿主不能引用未接收的来源", RejectAt(host, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Host = new()
                { Id = "host", ProcessId = 123, ImagePath = @"C:\Fixture\host.exe", SourceObservationIds = ["missing"] }
            }
        }));
        Check("组件同一 ID 不得跨来源和宿主重用", RejectAt(host, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Host = new()
                { Id = "source", ProcessId = 123, ImagePath = @"C:\Fixture\host.exe" }
            }
        }));
        Check("组件未知关系端点被拒绝", RejectAt(relation, b => b with
        { RelatedComponentFragment = b.RelatedComponentFragment! with { Relation = new("missing", "candidate", "Fixture", "fixture") } }));
        Check("组件图不接受外部 Finding ID 充当内部证据", RejectAt(candidate, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Candidate = new()
                { Id = "candidate", Path = @"C:\Fixture\module.dll", EvidenceObservationIds = ["finding"] }
            }
        }));
        Check("组件图不接受外部证书观察 ID", RejectAt(candidate, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Candidate = new()
                { Id = "candidate", Path = @"C:\Fixture\module.dll", EvidenceObservationIds = ["fixture-certificate-0"] }
            }
        }));
        Check("组件轮次必须指向真实候选 ID", RejectAt(round, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Round = new()
                { Number = 1, CandidateIds = ["source"] }
            }
        }));
        Check("组件超长单字段被拒绝且不部分提交", RejectAt(first, b => b with
        {
            RelatedComponentFragment = b.RelatedComponentFragment! with
            {
                Source = new()
                { Id = "source", Kind = "Run", Scope = "CurrentUser", UserSid = source.RelatedComponentDiagnostics!.TargetUserSid, RawCommand = new string('x', 65537) }
            }
        }));
        Check("组件完整 Data 传输旁路被拒绝", RejectAt(first, b => b with
        { Data = new ScanReport { ScanId = source.ScanId, RelatedComponentDiagnostics = source.RelatedComponentDiagnostics } }));

        ReportBatchReader untouched = new();
        bool rejected = false;
        try
        {
            untouched.Apply(new(0, new(0, 0, 0, 0, 0, 0, 0), new ScanReport { Findings = [new() { Title = "rejected" }] })
            {
                RelatedComponentFragment = frames[first].RelatedComponentFragment! with
                { Metadata = frames[first].RelatedComponentFragment!.Metadata with { SchemaVersion = 99 } }
            });
        }
        catch (InvalidDataException) { rejected = true; }
        Check("首片组件校验失败不留下空报告或偏移", rejected && untouched.Report is null && untouched.Count == 0);

        ScanReport extreme = RelatedBatchFixture();
        extreme.RelatedComponentDiagnostics!.Sources[0] = new()
        {
            Id = "source",
            Kind = "Run",
            Scope = "CurrentUser",
            UserSid = extreme.RelatedComponentDiagnostics.TargetUserSid,
            RawCommand = new string('中', 65536),
            Detail = new string('中', 8192),
            ResolvedTargets = [@"C:\Fixture\module.dll"]
        };
        int maximumFrame = 0;
        ReportBatchReader extremeReader = new();
        new ReportBatchWriter(batch =>
        {
            string wire = JsonSerializer.Serialize(new WorkerMessage { Type = WorkerMessageTypes.Checkpoint, Batch = batch }, options);
            maximumFrame = Math.Max(maximumFrame, wire.Length);
            extremeReader.Apply(JsonSerializer.Deserialize<WorkerMessage>(wire, JsonFile.Options)!.Batch!);
        }).Send(extreme, final: true);
        Check("组件最大命令与转义文本完整往返且每帧小于一 MiB", maximumFrame < 1024 * 1024 &&
            extremeReader.Report!.RelatedComponentDiagnostics!.Sources.Single().RawCommand.Length == 65536);

        bool RejectBeforeSend(ScanReport value)
        {
            int sent = 0;
            try { new ReportBatchWriter(_ => sent++).Send(value, final: true); }
            catch (InvalidDataException) { return sent == 0; }
            return false;
        }
        ScanReport tooMany = new()
        {
            RelatedComponentDiagnostics = new()
            { Sources = Enumerable.Range(0, 513).Select(i => new RelatedSourceObservation { Id = "s" + i, Kind = "Run", Scope = "LocalMachine" }).ToList() }
        };
        Check("组件累计来源数量在发送普通范围前拒绝", RejectBeforeSend(tooMany));
        string block = new('x', 32768);
        ScanReport tooMuchText = new()
        {
            RelatedComponentDiagnostics = new()
            { Sources = Enumerable.Range(0, 512).Select(i => new RelatedSourceObservation { Id = "s" + i, Kind = "Run", Scope = "LocalMachine", RawCommand = block }).ToList() }
        };
        Check("组件十六 MiB 累计文本预算在任何发送前拒绝", RejectBeforeSend(tooMuchText));
        ScanReport oversizedEnvelope = RelatedBatchFixture();
        oversizedEnvelope.WorkerDiagnostics = new("fixture", new string('中', 200000), "fixture", 0, 0, 0, DateTimeOffset.UtcNow);
        Check("组件过大的 WorkerMessage 信封在发送前拒绝", RejectBeforeSend(oversizedEnvelope));

        ScanReport empty = new() { RelatedComponentDiagnostics = new() { TargetUserSid = "" } };
        ReportBatchReader emptyReader = new(); new ReportBatchWriter(emptyReader.Apply).Send(empty, final: true);
        Check("组件空快照也有明确结束片", emptyReader.Report!.RelatedComponentDiagnostics is not null && !emptyReader.HasIncompleteRelatedComponentDiagnostics);
        ScanReport failedIdentity = new()
        {
            RelatedComponentDiagnostics = new()
            { TargetUserSid = "", Checks = [new() { Name = "未取得 SID", Status = DiagnosticReadStatus.Failed }] }
        };
        ReportBatchReader failedReader = new(); new ReportBatchWriter(failedReader.Apply).Send(failedIdentity, final: true);
        Check("组件缺少 SID 的失败检查可传输且不捏造来源", failedReader.Report!.RelatedComponentDiagnostics is { Sources.Count: 0, Hosts.Count: 0, Candidates.Count: 0 } d && d.Checks.Single().Status == DiagnosticReadStatus.Failed);
    }

    private static ScanReport RelatedBatchFixture()
    {
        const string sid = "S-1-5-21-10-20-30-1001";
        DateTimeOffset started = DateTimeOffset.UtcNow.AddMinutes(-1);
        return new()
        {
            StartedAtUtc = started,
            CompletedAtUtc = started.AddSeconds(3),
            Findings = [new() { Id = "finding", Title = "only an observation", CanRemediate = false, AssociationObservationIds = ["candidate"] }],
            CoverageNotes = ["original note"],
            RelatedComponentDiagnostics = new()
            {
                StartedAtUtc = started,
                CompletedAtUtc = started.AddSeconds(2),
                TargetUserSid = sid,
                AppliedLimits = new(),
                Sources = [new() { Id = "source", Kind = "Run", Scope = "CurrentUser", UserSid = sid,
                    Location = @"HKCU\Software\Fixture\Run", RawCommand = @"C:\Fixture\host.exe", ResolvedTargets = [@"C:\Fixture\module.dll"], Status = DiagnosticReadStatus.Complete }],
                Hosts = [new() { Id = "host", ProcessId = 123, StartedAtUtc = started.AddHours(-1), ImagePath = @"C:\Fixture\host.exe",
                    SourceObservationIds = ["source"], Status = DiagnosticReadStatus.Complete }],
                Candidates = [new() { Id = "candidate", Path = @"C:\Fixture\module.dll", SourceObservationIds = ["source"],
                    HostObservationIds = ["host"], Status = DiagnosticReadStatus.NotChecked, ContentStatus = DiagnosticReadStatus.NotChecked }],
                Checks = [new() { Id = "check", Name = "candidate content", ObservationId = "candidate", Status = DiagnosticReadStatus.NotChecked }],
                Relations = [new("source", "candidate", "SourceReferencesFile", "fixture path")],
                Rounds = [new() { Number = 1, StartedAtUtc = started.AddSeconds(1), CompletedAtUtc = started.AddSeconds(2),
                    CandidateIds = ["candidate"], MaximumBytes = 4096, BytesRead = 1, Status = DiagnosticReadStatus.NotChecked }]
            }
        };
    }
}
