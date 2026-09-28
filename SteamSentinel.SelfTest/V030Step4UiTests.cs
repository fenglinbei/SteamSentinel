using System.IO;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task<int> RunV030UiCorpusAsync(string root, string output)
    {
        root = Path.GetFullPath(root); output = Path.GetFullPath(output);
        if (!ContentDiscovery.IsLocalSafePath(root)) throw new InvalidDataException("Local static UI fixtures required.");
        Directory.CreateDirectory(output); List<object> summary = []; int failures = 0;
        foreach (string directory in Directory.EnumerateDirectories(root).Order(StringComparer.Ordinal))
        {
            SteamLayout layout = new(); layout.SteamRoots.Add(directory); ScanReport report = new();
            await new SteamSecurityScanner(RuleLoader.LoadEmbedded()).ScanAsync(layout, report);
            string name = Path.GetFileName(directory);
            Finding[] hits = report.Findings.Where(f => f.RuleId == "VPET-STEAM-UI-CHAIN").ToArray();
            bool verified = hits.Length == 1 && hits[0] is { IsKnownMalware: false, CanRemediate: false, SteamUiEvidence.EntryReferenceVerified: true, SteamUiEvidence.ActivationGateObserved: true };
            if (!verified) failures++;
            await JsonFile.WriteAtomicAsync(Path.Combine(output, name + ".json"), report);
            summary.Add(new { name, verified, chains = hits.Length, report.Coverage, files = hits.FirstOrDefault()?.SteamUiEvidence?.Files.Count });
        }
        await JsonFile.WriteAtomicAsync(Path.Combine(output, "summary.json"), summary);
        Console.WriteLine($"UI_CORPUS={summary.Count};FAIL={failures}"); return failures == 0 ? 0 : 1;
    }

    // Text-only fixtures. They are read by the scanner and never evaluated by a JS engine/browser.
    private const string V030Provider = "/*px:b*/ const HU='https://luminovastella.top/help'; const SU='https://luminovastella.top/support'; window.__pxH=HU; window.__pxS=SU; window.__pxA=0; const gate=Date.now(); /*px:e*/";
    private const string V030Routes = "const routes={SupportMessages:window.__pxS,HelpAppPage:window.__pxH,HelpFrontPage:window.__pxH};";
    private const string V030Entry = "<html><script defer=\"defer\" src=\"/sp.js?token=PRIVATE-QUERY\"></script></html>";
    private const string V030Style = ".URLBar {display:none!important} #ReportItemBtn{display:none!important}";

    private static async Task TestV030SteamUiAsync(string root)
    {
        string Hash(string text) => Hashing.Sha256Bytes(Encoding.UTF8.GetBytes(text));
        VPetSteamUiInspector Observe(string provider = V030Provider, string routes = V030Routes, string html = V030Entry,
            string providerPath = "steamui/sp.js", string routePath = "steamui/chunk.js")
        {
            VPetSteamUiInspector inspector = new(["luminovastella.top"]);
            inspector.Observe(providerPath, Hash(provider), provider); inspector.Observe(routePath, Hash(routes), routes);
            inspector.Observe("steamui/index.html", Hash(html), html); inspector.Observe("resource/webkit.css", Hash(V030Style), V030Style);
            return inspector;
        }
        var complete = Observe().Complete().Single();
        Check("0.3 第4步 HTML、PX 提供脚本、chunk 路由和 CSS 通过实际身份关联", complete.Evidence is
        { EntryReferenceVerified: true, SupportRoutesLinked: true, ActivationGateObserved: true, Files.Count: 4 } && complete.Target == "steamui/chunk.js");
        Check("0.3 第4步 各文件单独保留哈希且不携带查询令牌", complete.Evidence.Files.All(f => f.Sha256.Length == 64) &&
            !JsonSerializer.Serialize(complete.Evidence).Contains("PRIVATE-QUERY", StringComparison.Ordinal));
        foreach (string global in new[] { "window", "self", "globalThis" })
        {
            foreach (bool bracket in new[] { false, true })
            {
                string provider = V030Provider.Replace("window", global, StringComparison.Ordinal);
                string routes = V030Routes.Replace("window", global, StringComparison.Ordinal);
                if (bracket)
                    foreach (string property in new[] { "__pxS", "__pxH" })
                    { provider = provider.Replace("." + property, "['" + property + "']", StringComparison.Ordinal); routes = routes.Replace("." + property, "[\"" + property + "\"]", StringComparison.Ordinal); }
                Check($"0.3 第4步 全局属性路由 {global}/{bracket}", Observe(provider, routes).Complete().Single().Evidence.SupportRoutesLinked);
            }
        }
        foreach (string gate in new[] { "0", "1", "false", "true" })
            Check("0.3 第4步 潜伏开关值不影响静态组合识别：" + gate,
                Observe(V030Provider.Replace("__pxA=0", "__pxA=" + gate, StringComparison.Ordinal)).Complete().Single().Evidence.SupportRoutesLinked);
        Check("0.3 第4步 普通引号和正则中的引号不干扰后续代码定位",
            Observe("const r=/[\"']/g; const s='unrelated';" + V030Provider).Complete().Single().Evidence.SupportRoutesLinked);
        Check("0.3 第4步 带引号对象键仍关联真实属性",
            Observe(routes: V030Routes.Replace("SupportMessages:", "'SupportMessages':", StringComparison.Ordinal).Replace("HelpAppPage:", "\"HelpAppPage\":", StringComparison.Ordinal)).Complete().Single().Evidence.SupportRoutesLinked);
        foreach (string path in new[] { "../sp.js", "%2e%2e/sp.js", "https://example.invalid/sp.js", "//example.invalid/sp.js", "C:/sp.js", "\\sp.js" })
            Check("0.3 第4步 HTML 引用不越界、不解码或请求远端：" + path,
                !Observe(html: "<script src='" + path + "'></script>").Complete().Single().Evidence.EntryReferenceVerified);
        Check("0.3 第4步 HTML 注释中的引用不建立入口", !Observe(html: "<!--" + V030Entry + "-->").Complete().Single().Evidence.EntryReferenceVerified);
        var withBase = Observe(html: "<base href='/other/'><script src='sp.js'></script>");
        Check("0.3 第4步 未支持 HTML base 保留范围缺口", !withBase.Complete().Single().Evidence.EntryReferenceVerified && withBase.Incomplete);
        Check("0.3 第4步 clientui 和 steamui 不跨根关联", Observe(routePath: "clientui/chunk.js").Complete().All(m => !m.Evidence.SupportRoutesLinked));
        Check("0.3 第4步 仅提供脚本仍显示待核验的植入特征", Observe(routes: "const benign=1;").Complete().Single().Evidence is { SupportRoutesLinked: false, EntryReferenceVerified: true });

        string[] benignProviders =
        [
            "const date=Date.now(); fetch('https://example.invalid/settings');",
            "const normalSp=1;",
            V030Provider.Replace("/*px:b*/", "", StringComparison.Ordinal),
            V030Provider.Replace("window.__pxS=SU;", "", StringComparison.Ordinal),
            V030Provider.Replace("luminovastella.top", "luminovastella.top.example.invalid", StringComparison.Ordinal),
            V030Provider.Replace("https://luminovastella.top", "https://example.invalid/luminovastella.top", StringComparison.Ordinal),
            V030Provider.Replace("https://luminovastella.top", "https://luminovastella.top@example.invalid", StringComparison.Ordinal),
            "//" + V030Provider,
            "const documentation=`" + V030Provider + "`;",
            "/*px:b*/ // 'https://luminovastella.top/'\nwindow.__pxH=1;window.__pxS=1; /*px:e*/",
            "/*px:b*/ const text=\"window.__pxH=1;window.__pxS=1;\"; const url='https://luminovastella.top/'; /*px:e*/",
            "/*px:b*/ const r=/window.__pxH=1;window.__pxS=1;/; const url='https://luminovastella.top/'; /*px:e*/"
        ];
        foreach (string text in benignProviders)
            Check("0.3 第4步 同名脚本、普通日期与文本伪特征不判家族植入", Observe(text).Complete().Count == 0);
        foreach (string text in new[] { "//" + V030Routes, "const doc=`" + V030Routes + "`;", "const r=/SupportMessages:window.__pxS,HelpAppPage:window.__pxH/;" })
            Check("0.3 第4步 注释字符串及正则不伪装路由代码", Observe(routes: text).Complete().All(m => !m.Evidence.SupportRoutesLinked));
        var ambiguous = Observe(); ambiguous.Observe("steamui/second.js", Hash(V030Provider), V030Provider);
        Check("0.3 第4步 多个提供者不任意选择为确定路由链", ambiguous.Complete().All(m => !m.Evidence.SupportRoutesLinked) && ambiguous.Incomplete);
        var manyRefs = Observe(html: string.Concat(Enumerable.Repeat("<script src='/sp.js'></script>", 65)));
        manyRefs.Complete(); Check("0.3 第4步 引用计数超限保留缺口", manyRefs.Incomplete);
        VPetSteamUiInspector styles = new(["luminovastella.top"]);
        styles.Observe("steamui/index.html", Hash(V030Entry), V030Entry); styles.Observe("steamui/theme.css", Hash(V030Style), V030Style);
        Check("0.3 第4步 只有 HTML 或隐藏 CSS 不判恶意", styles.Complete().Count == 0);

        string directory = Path.Combine(root, "v030-steam-ui"), ui = Path.Combine(directory, "steamui"); Directory.CreateDirectory(ui);
        await File.WriteAllTextAsync(Path.Combine(ui, "index.html"), V030Entry);
        await File.WriteAllTextAsync(Path.Combine(ui, "sp.js"), V030Provider);
        await File.WriteAllTextAsync(Path.Combine(ui, "chunk.js"), V030Routes);
        await File.WriteAllTextAsync(Path.Combine(ui, "theme.css"), V030Style);
        SteamLayout layout = new(); layout.SteamRoots.Add(directory); ScanReport report = new();
        await new SteamSecurityScanner(RuleLoader.LoadEmbedded()).ScanAsync(layout, report);
        Finding? found = report.Findings.SingleOrDefault(f => f.RuleId == "VPET-STEAM-UI-CHAIN");
        Check("0.3 第4步 Steam 扫描集成仅提供复核且目标哈希来自同一快照", found is { IsKnownMalware: false, CanRemediate: false, SteamUiEvidence.Files.Count: 4 } &&
            found.Sha256 == await Hashing.Sha256FileAsync(Path.Combine(ui, "chunk.js")) && found.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        ReportBatchReader reader = new(); ReportBatchWriter writer = new(batch => reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
        writer.Send(report, true);
        Check("0.3 第4步 Steam 关联模型经过 Worker 协议往返", reader.Report?.Findings.Any(f => f.SteamUiEvidence is { SupportRoutesLinked: true, EntryReferenceVerified: true }) == true);
        string exported = Path.Combine(directory, "steam-ui-report.json"); await ReportExporter.ExportJsonAsync(report, exported);
        Check("0.3 第4步 导出只含关联代码与身份不泄漏脚本查询参数", !(await File.ReadAllTextAsync(exported)).Contains("PRIVATE-QUERY", StringComparison.Ordinal));
        using (FileStream locked = new(Path.Combine(ui, "sp.js"), FileMode.Open, FileAccess.Read, FileShare.None))
        {
            ScanReport incomplete = new(); await new SteamSecurityScanner(RuleLoader.LoadEmbedded()).ScanAsync(layout, incomplete);
            Check("0.3 第4步 关联源占用不能沿用旧结果或宣称检查完整", incomplete.Coverage == ScanCoverage.Partial && !incomplete.Findings.Any(f => f.RuleId == "VPET-STEAM-UI-CHAIN"));
        }
        await File.WriteAllBytesAsync(Path.Combine(ui, "invalid.js"), [0xff, 0xfe, 0xff]);
        ScanReport invalid = new(); await new SteamSecurityScanner(RuleLoader.LoadEmbedded()).ScanAsync(layout, invalid);
        Check("0.3 第4步 无法严格解码的 UI 文件明确 Partial", invalid.Coverage == ScanCoverage.Partial);
        foreach (string invalidPath in new[] { "../escape.js", "/absolute.js", "C:/outside.js", "steamui//sp.js", "steamui\n/sp.js" })
        {
            SteamUiEvidence value = new() { Files = [new(invalidPath, Hash("x"), [])] };
            bool rejected = false; try { value.Validate(); } catch (InvalidDataException) { rejected = true; }
            Check("0.3 第4步 关联协议拒绝无效路径字段", rejected);
        }
    }

    private static void TestV030ComponentLinks()
    {
        ContainerScanNode Node(string path, VPetComponentRole role = VPetComponentRole.Unknown, Guid? parent = null) => new()
        {
            DisplayPath = path,
            OriginalTarget = parent.HasValue ? "fixture.zip" : path,
            Sha256 = new string('A', 64),
            Length = 4096,
            Kind = parent.HasValue ? ContainerNodeKind.ArchiveMember : ContainerNodeKind.File,
            ParentId = parent,
            Depth = parent.HasValue ? 1 : 0,
            VPetFamily = role == VPetComponentRole.Unknown ? null : new()
            {
                SourceSha256 = new string('A', 64),
                Role = role,
                Status = role is VPetComponentRole.CredentialPayload or VPetComponentRole.UiPayload ? VPetFamilyStatus.Decoded : VPetFamilyStatus.CodeMatched,
                EnvelopeValidated = role != VPetComponentRole.ManagedWrapper,
                ReasonCode = "INERT-LINK-FIXTURE"
            }
        };
        foreach (Guid? parent in new Guid?[] { null, Guid.NewGuid() })
        {
            string prefix = parent.HasValue ? "fixture.zip!/modA" : "C:/fixture/modA";
            var wrapper = Node(prefix + "/plugin/wrapper.dll", VPetComponentRole.ManagedWrapper, parent);
            wrapper.VPetFamily!.RelatedNames.AddRange(["loader.dll", "original.orig.dll"]);
            var loader = Node(prefix + "/native/loader.dll", VPetComponentRole.Loader, parent);
            loader.VPetFamily!.RelatedNames.AddRange(["ui.dll", "credential.dll"]);
            var ui = Node(prefix + "/native/ui.dll", VPetComponentRole.UiPayload, parent);
            var credential = Node(prefix + "/native/credential.dll", VPetComponentRole.CredentialPayload, parent);
            var orig = Node(prefix + "/plugin/lib/original.orig.dll", parent: parent);
            var metadata = Node(prefix + "/info.lps", parent: parent);
            var other = Node(prefix.Replace("modA", "modB", StringComparison.Ordinal) + "/native/loader.dll", VPetComponentRole.Loader, parent);
            ContainerScanNode[] nodes = [wrapper, loader, ui, credential, orig, metadata, other];
            VPetComponentLinks.Link(nodes);
            Check("0.3 第4步 同一 MOD/归档中的外壳与加载器、原依赖和元数据对应", wrapper.VPetFamily.RelatedNodeIds.Count == 3 &&
                wrapper.VPetFamily.RelatedNodeIds.Contains(loader.NodeId) && wrapper.VPetFamily.RelatedNodeIds.Contains(orig.NodeId) && !wrapper.VPetFamily.RelatedNodeIds.Contains(other.NodeId));
            Check("0.3 第4步 加载器配置名只链接实际已解码的同目录载荷", loader.VPetFamily.RelatedNodeIds.SequenceEqual([ui.NodeId, credential.NodeId]));
            Check("0.3 第4步 关联修订不把原依赖声明为可信恢复件", wrapper.Revision == 1 && loader.Revision == 1 && wrapper.VPetFamily.Signals.Contains("VPET-LINK-UNTRUSTED-ORIGINAL") && orig.VPetFamily is null);
            VPetComponentLinks.Link(nodes); Check("0.3 第4步 重复关联不会重复 ID 或虚增修订", wrapper.Revision == 1 && loader.Revision == 1);
            wrapper.VPetFamily.RelatedNodeIds.Clear(); loader.VPetFamily.RelatedNodeIds.Clear();
            var collision = Node(loader.DisplayPath, VPetComponentRole.Loader, parent);
            VPetComponentLinks.Link([wrapper, loader, collision, other]);
            Check("0.3 第4步 展示名称歧义不建立实际成员关联", wrapper.VPetFamily.RelatedNodeIds.Count == 0);
        }
        Guid one = Guid.NewGuid(), two = Guid.NewGuid();
        var left = Node("same.zip!/native/loader.dll", VPetComponentRole.Loader, one); left.VPetFamily!.RelatedNames.AddRange(["ui.dll", "credential.dll"]);
        var right = Node("same.zip!/native/ui.dll", VPetComponentRole.UiPayload, two);
        VPetComponentLinks.Link([left, right]);
        Check("0.3 第4步 同名嵌套归档不能跨父容器链接", left.VPetFamily.RelatedNodeIds.Count == 0);
    }
}
