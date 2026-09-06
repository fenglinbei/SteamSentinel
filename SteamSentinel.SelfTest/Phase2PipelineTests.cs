using System.IO;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestPhase2PipelineAsync(string root)
    {
        string directory = Path.Combine(root, "phase2-pipeline");
        Directory.CreateDirectory(directory);
        string[] paths = Enumerable.Range(0, 4).Select(i => Path.Combine(directory, $"inert-{i}.txt")).ToArray();
        foreach (string path in paths) await File.WriteAllTextAsync(path, "Inert association fixture. It is never executed.");
        RuleSet rules = RuleLoader.LoadEmbedded();
        const string sid = "S-1-5-21-123-456-789-1001";
        static RelatedArtifactExpansion EmptyExpansion() => new([], [], []);
        static ScanOptions Options() => new()
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = true,
            IncludeRelatedContent = true,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true
        };
        RelatedComponentDiagnosticReport Graph(params string[] files)
        {
            RelatedComponentDiagnosticReport graph = new() { TargetUserSid = sid };
            foreach (string path in files) graph.Candidates.Add(new() { Path = path, Reason = "inert explicit target" });
            return graph;
        }
        static Finding Proof(string path, string hash) => new()
        {
            RuleId = "INERT-CONTENT-PROOF",
            Category = FindingCategory.File,
            Target = path,
            Sha256 = hash,
            TargetSha256 = hash,
            Severity = FindingSeverity.High,
            Score = 95,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        static ScanReport Content(ScanOptions options)
        {
            ScanReport content = new() { Mode = ScanMode.Custom, ContentScanSettings = options };
            foreach (string path in options.CustomRoots) content.RootSummaries.Add(new(path, ScanCoverage.Complete, 0, 0, 1));
            return content;
        }

        int discovery = 0, workers = 0, closures = 0;
        ScanOptions original = Options();
        ScanReport report = new() { Mode = ScanMode.Full, ContentScanSettings = original, RelatedComponentDiagnostics = Graph(paths[0]) };
        report.RootSummaries.Add(new(paths[0], ScanCoverage.Complete, 0, 0, 1));
        RelatedComponentPipeline pipeline = new(rules, (_, output, _, _) =>
        {
            int index = Math.Min(++discovery, 3);
            output.Candidates.Add(new() { Path = paths[index] });
        }, () => sid, (findings, _, _, _) =>
        {
            closures++;
            Finding[] found = findings.Where(f => f.Target == paths[1]).Select(f => new Finding
            {
                RuleId = "INERT-LATE-HOST",
                Category = FindingCategory.Process,
                Target = paths[0],
                ProcessId = 123,
                RelatedFilePath = f.Target,
                RelatedFileSha256 = f.TargetSha256,
                CanRemediate = false
            }).ToArray();
            return Task.FromResult(new RelatedArtifactExpansion(found, [], []));
        });
        await pipeline.CompleteAsync(report, original, async (options, _, _) =>
        {
            workers++;
            Check("第二批补查固定精确目标且不再次收集系统", options.Mode == ScanMode.Custom && !options.IncludeSystem &&
                !options.IncludeWorkshop && !options.IncludeRelatedContent && options.HashEveryFile && !options.UseAmsi && options.InspectArchives);
            ScanReport content = Content(options);
            foreach (string path in options.CustomRoots) content.Findings.Add(Proof(path, await Hashing.Sha256FileAsync(path)));
            return content;
        });
        Check("第二批未知组件最多两轮且末次内容证据回填宿主", workers == 2 && report.RelatedComponentDiagnostics!.Rounds.Count == 2 &&
            closures >= 1 && report.Findings.Any(f => f.RuleId == "INERT-LATE-HOST"));
        Check("第二批补查保留原范围和内容设置对象", report.Mode == ScanMode.Full && ReferenceEquals(report.ContentScanSettings, original));
        Check("第二批内容风险分级不提升原处理资格", report.Findings.Where(f => f.RuleId == "INERT-CONTENT-PROOF").All(f =>
            f.AssociationEvidenceTier == RelatedEvidenceTier.RelatedRisk && f.AssociationObservationIds.Count == 1 && f.CanRemediate));
        Check("第二批累计字节与每轮记录有界", report.RelatedComponentDiagnostics!.Rounds.All(r => r.BytesRead >= 0 && r.BytesRead <= r.MaximumBytes));

        int repeated = 0;
        ScanReport cycle = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        RelatedComponentPipeline cyclic = new(rules, (_, output, _, _) => output.Candidates.Add(new() { Path = paths[0] }), () => sid,
            (_, _, _, _) => Task.FromResult(EmptyExpansion()));
        await cyclic.CompleteAsync(cycle, Options(), (options, _, _) => { repeated++; return Task.FromResult(Content(options)); });
        Check("第二批循环候选按路径去重只扫描一次", repeated == 1 && cycle.RelatedComponentDiagnostics!.Candidates.Count == 1);

        ScanReport limited = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        int limitedCalls = 0;
        await cyclic.CompleteAsync(limited, Options(), (options, _, _) => { limitedCalls++; return Task.FromResult(Content(options)); },
            limits: new() { MaximumTotalBytes = 1 });
        Check("第二批不足字节预算不读取候选且明确缺口", limitedCalls == 0 && limited.Coverage == ScanCoverage.Partial &&
            limited.RelatedComponentDiagnostics!.Candidates[0].ContentStatus == DiagnosticReadStatus.LimitReached);

        ScanReport occupied = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        using (FileStream held = new(paths[0], FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await cyclic.CompleteAsync(occupied, Options(), (options, _, _) => Task.FromResult(Content(options)));
        Check("第二批占用目标保留未核验且不强制解锁", occupied.Coverage == ScanCoverage.Partial &&
            occupied.RelatedComponentDiagnostics!.Candidates[0].ContentStatus != DiagnosticReadStatus.Complete);

        ScanReport cancelled = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        cancelled.Findings.Add(new() { RuleId = "BEFORE-CANCEL", Target = "inert prior observation" });
        using (CancellationTokenSource cancellation = new())
        {
            cancellation.Cancel();
            await cyclic.CompleteAsync(cancelled, Options(), (options, _, _) => Task.FromResult(Content(options)), token: cancellation.Token);
        }
        Check("第二批取消保留先前结果并标明未完成", cancelled.Coverage == ScanCoverage.Partial &&
            cancelled.Findings.Any(f => f.RuleId == "BEFORE-CANCEL") && cancelled.RelatedComponentDiagnostics!.Checks.Any(c => c.Status == DiagnosticReadStatus.Cancelled));

        ScanReport partial = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        await cyclic.CompleteAsync(partial, Options(), async (options, _, _) =>
        {
            ScanReport content = Content(options); content.Coverage = ScanCoverage.Partial;
            content.Findings.Add(Proof(paths[0], await Hashing.Sha256FileAsync(paths[0])));
            content.WorkerDiagnostics = new("inert supplemental stage", paths[0], "inert worker stopped", 0, 0, 0, DateTimeOffset.UtcNow);
            content.CoverageNotes.Add("inert worker terminated after checkpoint"); return content;
        });
        Check("第二批工作进程部分结果和未完成状态均保留", partial.Coverage == ScanCoverage.Partial &&
            partial.Findings.Any(f => f.RuleId == "INERT-CONTENT-PROOF") && partial.CoverageNotes.Any(n => n.Contains("terminated")));
        Check("第二批其他检查缺口不覆盖此目标的已完成摘要", partial.RelatedComponentDiagnostics!.Candidates[0].ContentStatus == DiagnosticReadStatus.Complete);
        Check("第二批补查失败保留最新工作进程最后路径", partial.WorkerDiagnostics?.LastPath == paths[0] && partial.WorkerDiagnostics.Stage == "inert supplemental stage");

        ScanReport mismatch = new() { RelatedComponentDiagnostics = Graph(paths[0]) };
        await cyclic.CompleteAsync(mismatch, Options(), (options, _, _) =>
        { ScanReport content = Content(options); content.Findings.Add(Proof(paths[0], new string('a', 64))); return Task.FromResult(content); });
        Check("第二批文件身份冲突拒绝该目标内容处置证据", mismatch.Coverage == ScanCoverage.Partial &&
            !mismatch.Findings.Any(f => f.RuleId == "INERT-CONTENT-PROOF"));

        ScanReport signatureOnly = new() { RelatedComponentDiagnostics = Graph() };
        signatureOnly.RelatedComponentDiagnostics.Hosts.Add(new() { ProcessId = 1, ImagePath = paths[0], SignatureStatus = "NotChecked" });
        RelatedComponentPipeline noDiscovery = new(rules, (_, _, _, _) => { }, () => sid, (_, _, _, _) => Task.FromResult(EmptyExpansion()));
        int signatures = 0;
        await noDiscovery.CompleteAsync(signatureOnly, Options(), (options, _, _) =>
        {
            signatures++;
            Check("第二批准许无新增内容候选的受限签名检查且预算分配守恒", options.CustomRoots.Count == 0 && options.RelatedSignaturePaths.Count == 1 &&
                options.MaximumContentBytes >= options.MaximumRelatedSignatureBytes && options.MaximumContentBytes + options.MaximumExpandedBytes <= 1024L * 1024 * 1024);
            ScanReport content = Content(options);
            content.Findings.Add(new() { RuleId = "ASSOCIATION-HOST-SIGNATURE", Target = paths[0], ConfigurationKind = "Valid", Description = "inert offline signature" });
            return Task.FromResult(content);
        });
        Check("第二批签名仅回填诊断不创建豁免或处置项", signatures == 1 && signatureOnly.RelatedComponentDiagnostics.Hosts[0].SignatureStatus == "Valid" &&
            !signatureOnly.Findings.Any(f => f.CanRemediate || f.RuleId == "ASSOCIATION-HOST-SIGNATURE"));

        RelatedComponentDiagnosticReport first = Graph(paths[0]), next = Graph(paths[0]);
        RelatedSourceObservation source = new() { Kind = "Run", Location = "inert", RawCommand = paths[0] };
        next.Sources.Add(source); next.Candidates[0].SourceObservationIds.Add(source.Id);
        RelatedHostObservation host = new() { ProcessId = 23, ImagePath = paths[1], StartedAtUtc = DateTimeOffset.UtcNow };
        next.Hosts.Add(host); next.Candidates[0].HostObservationIds.Add(host.Id);
        next.Relations.Add(new(host.Id, next.Candidates[0].Id, "ObservedLoadedModulePath", "inert stable observation"));
        string oldId = first.Candidates[0].Id;
        RelatedComponentPipeline.MergeDiscovery(first, next, new());
        RelatedComponentPipeline.MergeDiscovery(first, next, new());
        Check("第二批多轮图合并重映射ID并保留已有候选", first.Candidates.Count == 1 && first.Candidates[0].Id == oldId &&
            first.Sources.Count == 1 && first.Hosts.Count == 1 && first.Relations.Single().ToId == oldId);
        RelatedComponentDiagnosticReport overflow = Graph(paths[1]);
        RelatedComponentPipeline.MergeDiscovery(first, overflow, new() { MaximumCandidates = 1 });
        Check("第二批累计图限额保留原记录并明确截断", first.Candidates.Count == 1 && first.Checks.Any(c => c.Status == DiagnosticReadStatus.LimitReached));
        ScanReport observation = new() { RelatedComponentDiagnostics = first };
        observation.Findings.Add(new()
        {
            RuleId = "NAME-ONLY",
            Category = FindingCategory.File,
            Target = paths[0],
            Severity = FindingSeverity.Medium,
            Description = "mitmproxy / PAC IP / self-signed are not standalone evidence"
        });
        RelatedComponentPipeline.AssociateEvidence(observation);
        Check("第二批仅名称IP同目录线索不获得证据层级或动作", observation.Findings[0].AssociationEvidenceTier is null && !observation.Findings[0].CanRemediate);

        ScanReport noSid = new(); int unauthorizedReads = 0;
        new RelatedComponentPipeline(rules, (_, _, _, _) => unauthorizedReads++, () => throw new UnauthorizedAccessException(), null)
            .CollectInitial(noSid, Options());
        Check("第二批身份读取失败不执行来源采集并保留报告", unauthorizedReads == 0 && noSid.RelatedComponentDiagnostics is not null && noSid.Coverage == ScanCoverage.Partial);

        ScanReport crowded = new() { RelatedComponentDiagnostics = Graph() };
        for (int i = 0; i < 64; i++)
        {
            string old = Path.Combine(directory, $"old-{i}.txt"); await File.WriteAllTextAsync(old, "inert old proof " + i);
            crowded.Findings.Add(Proof(old, await Hashing.Sha256FileAsync(old)));
        }
        bool newProofClosed = false;
        RelatedComponentPipeline crowdedPipeline = new(rules,
            (_, output, _, _) => output.Candidates.Add(new() { Path = paths[2] }), () => sid,
            (proofs, _, _, _) => { newProofClosed |= proofs.Any(f => f.Target == paths[2]); return Task.FromResult(EmptyExpansion()); });
        await crowdedPipeline.CompleteAsync(crowded, Options(), async (options, _, _) =>
        { ScanReport content = Content(options); content.Findings.Add(Proof(paths[2], await Hashing.Sha256FileAsync(paths[2]))); return content; });
        Check("第二批64条旧证据不挤掉新模块的关联回填", newProofClosed);

        string oldHash = await Hashing.Sha256FileAsync(paths[3]);
        ScanReport replaced = new() { RelatedComponentDiagnostics = Graph(paths[3]) };
        Finding oldProof = Proof(paths[3], oldHash); replaced.Findings.Add(oldProof);
        replaced.RootSummaries.Add(new(paths[3], ScanCoverage.Complete, 0, 1, 1));
        await File.WriteAllTextAsync(paths[3], "Another inert version now at the same path.");
        int replacementsChecked = 0;
        RelatedComponentPipeline replacedPipeline = new(rules, (_, output, _, _) =>
        {
            RelatedHostObservation newer = new() { ProcessId = 900, ImagePath = paths[0], StartedAtUtc = DateTimeOffset.UnixEpoch, SignatureStatus = "Unsigned" };
            output.Hosts.Add(newer);
            output.Candidates.Add(new() { Path = paths[3], HostObservationIds = [newer.Id] });
        }, () => sid, (_, _, _, _) => Task.FromResult(EmptyExpansion()));
        await replacedPipeline.CompleteAsync(replaced, Options(), (options, _, _) =>
        { replacementsChecked++; return Task.FromResult(Content(options)); });
        Check("第二批同路径换文件不把旧内容哈希接到新宿主", oldProof.AssociationObservationIds.Count == 0 && oldProof.AssociationEvidenceTier is null &&
            replaced.RelatedComponentDiagnostics!.Candidates[0].Sha256 != oldHash);
        Check("第二批当前替换身份重新扫描一次并保留历史身份缺口", replacementsChecked == 1 &&
            replaced.RelatedComponentDiagnostics!.Checks.Any(c => c.Name == "关联文件身份变化") && replaced.Coverage == ScanCoverage.Partial);
    }
}
