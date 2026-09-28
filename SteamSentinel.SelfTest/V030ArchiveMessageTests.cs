using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV030ArchiveMessageFlows()
    {
        MsiActionAnalysis analysis;
        using (DisplayText.UseCulture(DisplayText.Chinese)) analysis = MsiActionAnalyzer.Analyze(MsiLinkedModel());
        Finding finding = new() { RuleId = "INERT-MSI", EvidenceLines = analysis.Evidence.Texts.Concat(analysis.CoverageGaps.Texts) };
        string saved = JsonSerializer.Serialize(finding, JsonFile.Options);
        Finding received = JsonSerializer.Deserialize<Finding>(saved, JsonFile.Options)!;
        using (DisplayText.UseCulture(DisplayText.English))
        {
            Check("后台消息 MSI关联判定保持原值且摘要完整显示英语", analysis.ContentSignals.Count == 0 && analysis.LinkedSignals.Count > 0 &&
                received.EvidenceLineMessages?.Count > 0 && !V030HasHan(received.EvidenceDisplay));
            Check("后台消息 多行证据切换语言不改保存数据", saved == JsonSerializer.Serialize(received, JsonFile.Options) && received.Evidence.Contains("动作", StringComparison.Ordinal));
            using MemoryStream malformed = new([0, 1, 2]);
            ContainerRangeRarInspection range = ContainerRangeInspector.InspectRar(malformed);
            ContainerEngineObservation engine = new() { Engine = "INERT", DetailText = range.DetailText };
            var engineReceived = JsonSerializer.Deserialize<ContainerEngineObservation>(JsonSerializer.Serialize(engine, JsonFile.Options), JsonFile.Options)!;
            Check("后台消息 范围异常到引擎记录保留原因与英语", range.Status == ContainerRangeStatus.Malformed && engineReceived.DetailMessage is not null &&
                engineReceived.DetailText.Display.Contains("RAR4/RAR5", StringComparison.Ordinal) && !V030HasHan(engineReceived.DetailText.Display));
            for (int i = 1; i <= 7; i++)
                Check("后台消息 有界拼接保留分隔符与原文 " + i, MessageText.Join("/", Enumerable.Repeat(MessageText.Create("Ui.Language.Saved"), i)).Display ==
                    string.Join("/", Enumerable.Repeat(DisplayText.Get("Ui.Language.Saved"), i)));
        }
        ScanReport report = new() { Findings = [received] };
        List<ReportBatch> frames = []; new ReportBatchWriter(frames.Add).Send(report, true);
        ReportBatchReader reader = new();
        foreach (ReportBatch frame in frames) reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(frame, JsonFile.Options), JsonFile.Options)!);
        Check("后台消息 多行证据经过Worker分片保留索引", reader.Report!.Findings[0].EvidenceLineMessages?.Count == received.EvidenceLineMessages?.Count);
        Finding bad = new() { Evidence = "one line", EvidenceLineMessages = new() { [1] = MessageText.Create("Ui.Language.Saved").Message! } };
        ReportBatchReader rejected = new();
        Check("后台消息 越界证据行索引在提交前拒绝", V020Throws<InvalidDataException>(() => rejected.Apply(new(0, new(0, 0, 0, 0, 0, 0, 0), new() { Findings = [bad] }))) && rejected.Report is null);
        Finding replacement = new() { EvidenceLineMessages = received.EvidenceLineMessages, EvidenceText = "replacement" };
        Check("后台消息 替换整段证据清除旧行描述", replacement.EvidenceLineMessages is null && replacement.EvidenceDisplay == "replacement");
        ContainerScanReport container = new(); container.AddCheck(MessageText.Create("Ui.Language.Saved"));
        ContainerScanMetadata metadata = ContainerScanFragments.Metadata(container);
        ContainerScanFragments.ValidateMetadata(metadata);
        Check("后台消息 容器说明非法索引被拒绝", V020Throws<InvalidDataException>(() => ContainerScanFragments.ValidateMetadata(metadata with
        { CheckMessages = new() { [-1] = MessageText.Create("Ui.Language.Saved").Message! } })));
    }
}
