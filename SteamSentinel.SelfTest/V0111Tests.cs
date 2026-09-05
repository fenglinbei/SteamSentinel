using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV0111Async(string root, RuleSet rules)
    {
        string folder = Path.Combine(root, "v0111"); Directory.CreateDirectory(folder);
        SteamLayout layout = new();
        foreach (string library in new[] { "lib-one", "lib-two" })
        {
            string path = Path.Combine(folder, library); Directory.CreateDirectory(path); layout.LibraryRoots.Add(path);
        }
        layout.SteamRoots.Add(layout.LibraryRoots[0]);
        foreach (var (library, appId) in new[] { (0, "431960"), (0, "3167020"), (1, "4000") })
        {
            string project = Path.Combine(layout.LibraryRoots[library], "steamapps", "workshop", "content", appId, "123456");
            Directory.CreateDirectory(project);
            await File.WriteAllTextAsync(Path.Combine(project, "normal.dll"), "harmless fixture, no executable content");
            if (appId == "431960") await File.WriteAllTextAsync(Path.Combine(project, "project.json"), "{\"type\":\"scene\",\"title\":\"fixture\"}");
        }
        string mod = Path.Combine(layout.LibraryRoots[1], "steamapps", "common", "Duckov", "Duckov_Data", "Mods");
        Directory.CreateDirectory(mod);
        await File.WriteAllTextAsync(Path.Combine(layout.LibraryRoots[1], "steamapps", "appmanifest_3167020.acf"),
            "\"AppState\"{\"appid\"\"3167020\"\"name\"\"Duckov\"\"installdir\"\"Duckov\"}");
        await File.WriteAllTextAsync(Path.Combine(layout.LibraryRoots[1], "steamapps", "appmanifest_999.acf"),
            "\"appid\"\"999\"\"installdir\"\"..\\escape\"");
        string plugin = Path.Combine(layout.SteamRoots[0], "millennium", "plugins"); Directory.CreateDirectory(plugin);
        ContentDiscovery.Populate(layout);
        Check("全 AppID 多库发现三个工坊入口", layout.WorkshopRoots.Count == 3 && layout.WorkshopRoots.Any(p => p.EndsWith("4000")));
        Check("鸭科夫 MOD 与 Steam 插件入口自动发现", layout.ContentRoots.Any(r => r.Path == mod && r.AppId == "3167020") && layout.ContentRoots.Any(r => r.Path == plugin));
        Check("游戏清单不允许目录穿越", layout.Games.All(g => g.AppId != "999"));
        ContentDiscovery.Populate(layout);
        Check("重复发现不重复累计项目", layout.ContentRoots.Count(r => r.Kind == "workshop") == 3);
        Check("任意工坊 AppID 进程路径可关联", ContentDiscovery.IsWorkshopContentPath(Path.Combine(layout.WorkshopRoots[2], "123456", "mod.dll")));
        Check("网络路径、设备路径和 ADS 被拒绝", !ContentDiscovery.IsLocalSafePath(@"\\example.invalid\share\a") &&
            !ContentDiscovery.IsLocalSafePath(@"\\?\C:\x") && !ContentDiscovery.IsLocalSafePath(Path.Combine(folder, "file:stream")));
        ScanReport normal = await new ScanCoordinator(rules, layout).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = true,
            IncludeRelatedContent = true,
            UseAmsi = false
        });
        Check("普通游戏 MOD 不按壁纸 project.json 或 DLL 类型误报", normal.Findings.All(f => f.RuleId is not ("WORKSHOP-PROJECT-METADATA" or "WORKSHOP-EXECUTABLE-CONTENT")));
        Check("扫描报告保留全部工坊来源", normal.Metrics.WorkshopItemsVisited == 3 && normal.ContentSources.Any(p => p.Contains("4000/123456")));
        Check("恶意 MOD 的前两环按精确内容加入规则", rules.KnownHashes.Count(r => r.Malware && r.Id.StartsWith("STEAMRED-DUCKOV-")) == 3);
        Check("MSI 最终载荷未证实时仍只供人工复核", rules.KnownHashes.Where(r => r.Id.StartsWith("REVIEW-MSI")).All(r => !r.Malware && r.Remediable));

        const string script = "Invoke-WebRequest https://example.invalid/file; Start-Process steamprocess; Add-MpPreference -ExclusionPath millennium";
        Check("ClickFix 组合规则有多个独立信号", ScriptSignals.Analyze(script).Count >= 2);
        Check("脚本 Base64 静态读取不执行", ScriptSignals.Analyze("powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script))).Count >= 2);
        Check("脚本字面量拼接可规范化", ScriptSignals.Normalize("'Down' + 'loadString'").Contains("DownloadString"));
        Check("单独安装正常插件不判为恶意脚本", ScriptSignals.Analyze("millennium plugin normal; https://example.invalid/docs").Count == 0);
        Check("Wallpaper 举报双信号规则与正常条件区分", WallpaperUiInspector.HasCombinedSuppression("canReport=false; .report-button{display:none}") &&
            !WallpaperUiInspector.HasCombinedSuppression("canReport=user.canReport; .report-button{display:none}"));
        Check("URL 查询参数与令牌脱敏", !ScriptSignals.Redact("https://example.invalid/?token=secret&u=123 password=abc").Contains("secret") &&
            !ScriptSignals.Redact("password=abc").Contains("abc"));

        byte[] shortcut = CreateBoundedShortcut(Path.Combine(folder, "payload.exe"), "--normal");
        ShortcutInspection shortcutResult = ShortcutInspector.Inspect(shortcut);
        Check("LNK 只读提取目标和参数", shortcutResult.Complete && shortcutResult.Arguments == "--normal" && shortcutResult.Target!.EndsWith("payload.exe"));
        Check("损坏 LNK 不抛出整个扫描异常", !ShortcutInspector.Inspect(shortcut.AsSpan(0, 50)).Complete);
        Check("UNC LNK 不解析网络目标", !ShortcutInspector.Inspect(CreateBoundedShortcut(@"\\example.invalid\a.exe", "")).Complete);

        string cab = Path.Combine(folder, "fixture.cab");
        await File.WriteAllBytesAsync(cab, CreateStoredCabinet("../escape.txt", "harmless cabinet fixture"));
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection result = StructuredContainerInspector.ReadCabinet(cab, temporary, 4096, 4096, 8, default);
            Check("CAB 只读提取无害成员", result.Notes.Count == 0 && result.Members.Count == 1 && await File.ReadAllTextAsync(result.Members[0].Path) == "harmless cabinet fixture");
            Check("CAB 路径穿越名称只能写入随机临时文件", result.Members.All(m => m.Path.StartsWith(temporary.Path + Path.DirectorySeparatorChar) && m.Path.EndsWith(".scan")) && !File.Exists(Path.Combine(folder, "escape.txt")));
        }
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection result = StructuredContainerInspector.ReadCabinet(cab, temporary, 1, 1, 8, default);
            Check("CAB 超限不提取并保留缺口", result.Notes.Count > 0 && result.Members.Count == 0);
        }
        string msi = Path.Combine(folder, "fixture.msi");
        CreateReadOnlyMsiFixture(msi);
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection result = StructuredContainerInspector.ReadMsi(msi, temporary, 4096, 4096, 8, default);
            Check("MSI 固定 SELECT 读取自定义动作不执行", result.Recognized && result.Metadata.Any(s => s.Contains("fixture-marker-never-executed")));
        }
        ScanReport bounded = new();
        using (ContentScanner scanner = new(rules)) await scanner.ScanRootAsync(cab, bounded,
            new ScanOptions { IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, MaximumContentBytes = 1, UseAmsi = false }, new NullPasswordProvider());
        Check("单文件入口也遵守全局字节预算", bounded.Coverage == ScanCoverage.Partial && bounded.Metrics.BytesHashed == 0);
        ScanReport installer = new();
        using (ContentScanner scanner = new(rules)) await scanner.ScanRootAsync(msi, installer, ContentOptions(), new NullPasswordProvider());
        Check("安装包进入生产扫描链并输出结构证据", installer.Findings.Any(f => f.RuleId == "INSTALLER-STRUCTURE") && installer.Findings.All(f => !f.IsKnownMalware));
        string knownFile = Path.Combine(mod, "binding.dll"); await File.WriteAllTextAsync(knownFile, "harmless binding fixture");
        string knownHash = await Hashing.Sha256FileAsync(knownFile);
        RuleSet fixtureRules = new() { KnownHashes = [new HashRule { Id = "FIXTURE", Sha256 = knownHash, Malware = true }] };
        var match = await new RelatedArtifactScanner(fixtureRules).MatchCommandAsync('"' + knownFile + '"', new ScanReport(), default);
        Check("持久化关联使用文件内容而非名称", match is { } found && found.Hash == knownHash);
        Check("相同文件名不自动判为恶意", await new RelatedArtifactScanner(rules).MatchCommandAsync('"' + knownFile + '"', new ScanReport(), default) is null);
        Finding host = new()
        {
            Target = knownFile,
            Sha256 = knownHash,
            RelatedFilePath = knownFile,
            RelatedFileSha256 = knownHash,
            ProcessId = 1234,
            ProcessStartedAtUtc = DateTimeOffset.UtcNow,
            IsKnownMalware = true,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.StopHostProcess]
        };
        RemediationPlan hostPlan = await new RemediationPlanBuilder(fixtureRules).BuildAsync([host], false);
        Check("恶意模块的正常宿主只关闭，不隔离或封网", hostPlan.Actions.Count == 1 && hostPlan.Actions[0].Type == RemediationActionType.StopHostProcess && hostPlan.Actions[0].ProcessStartedAtUtc == host.ProcessStartedAtUtc);
        BrokerEngine broker = new();
        MethodInfo validate = typeof(BrokerEngine).GetMethod("ValidateAction", BindingFlags.Instance | BindingFlags.NonPublic)!;
        bool Rejects(RemediationAction action) { try { validate.Invoke(broker, [action]); return false; } catch (TargetInvocationException) { return true; } }
        Check("Broker 拒绝无恶意绑定的任意服务处置", Rejects(new() { Type = RemediationActionType.DisableService, Target = "Anything", ConfigurationKind = "2", ConfigurationSnapshot = "x" }));
        Check("Broker 拒绝伪造关联 hash", Rejects(new() { Type = RemediationActionType.DisableService, Target = "Anything", ConfigurationKind = "2", ConfigurationSnapshot = "x", RelatedFilePath = knownFile, RelatedFileSha256 = knownHash }));
        Check("正常 Millennium 或任意代理排除项不进入插件恢复范围", !ProtectionConfiguration.IsRelatedExclusion(layout.SteamRoots[0], Path.Combine(folder, "Clash")) &&
            ProtectionConfiguration.PluginRoot(layout, Path.Combine(plugin, "normal", "index.js")) is null);
        Check("配置恢复拒绝非样本特征的放行规则", !ProtectionConfiguration.IsRelatedFirewall(layout.SteamRoots[0], new("r", "legitimate", Path.Combine(layout.SteamRoots[0], "steam.exe"), 2, 2, 1, 7)));
        ScanReport merged = ScanReportMerger.Merge(new() { CandidateRoots = { mod } }, new() { ContentSources = { "workshop:4000" } });
        Check("前后阶段合并保留候选落点和来源", merged.CandidateRoots.Contains(mod) && merged.ContentSources.Contains("workshop:4000"));
    }

    private static byte[] CreateBoundedShortcut(string target, string arguments)
    {
        using MemoryStream memory = new(); using BinaryWriter writer = new(memory);
        writer.Write(76); writer.Write(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray()); writer.Write(0xA8u); writer.Write(new byte[52]);
        foreach (string text in new[] { target, arguments }) { writer.Write((ushort)text.Length); writer.Write(Encoding.Unicode.GetBytes(text)); }
        writer.Write(0u); return memory.ToArray();
    }

    private static byte[] CreateStoredCabinet(string name, string content)
    {
        byte[] fileName = Encoding.ASCII.GetBytes(name + "\0"), payload = Encoding.UTF8.GetBytes(content);
        uint dataOffset = (uint)(44 + 16 + fileName.Length);
        using MemoryStream memory = new(); using BinaryWriter writer = new(memory);
        writer.Write("MSCF"u8); writer.Write(0u); writer.Write(dataOffset + 8u + (uint)payload.Length); writer.Write(0u); writer.Write(44u); writer.Write(0u);
        writer.Write((byte)3); writer.Write((byte)1); writer.Write((ushort)1); writer.Write((ushort)1); writer.Write((ushort)0); writer.Write((ushort)123); writer.Write((ushort)0);
        writer.Write(dataOffset); writer.Write((ushort)1); writer.Write((ushort)0);
        writer.Write((uint)payload.Length); writer.Write(0u); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)0x20); writer.Write(fileName);
        writer.Write(0u); writer.Write((ushort)payload.Length); writer.Write((ushort)payload.Length); writer.Write(payload);
        return memory.ToArray();
    }

    private static void CreateReadOnlyMsiFixture(string path)
    {
        if (MsiFixture.Open(path, new IntPtr(3), out uint database) != 0) throw new IOException("Cannot create test MSI database");
        try
        {
            foreach (string sql in new[] {
                "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) LOCALIZABLE PRIMARY KEY `Action`)",
                "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('fixture',51,'PROPERTY','fixture-marker-never-executed')" })
            {
                uint code = MsiFixture.View(database, sql, out uint view);
                if (code != 0) throw new IOException("MSI fixture view " + code);
                try { code = MsiFixture.Execute(view, 0); if (code != 0) throw new IOException("MSI fixture query " + code); }
                finally { MsiFixture.Close(view); }
            }
            if (MsiFixture.Commit(database) != 0) throw new IOException("MSI fixture commit failed");
        }
        finally { MsiFixture.Close(database); }
    }

    private static class MsiFixture
    {
        [DllImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", CharSet = CharSet.Unicode)] internal static extern uint Open(string path, IntPtr mode, out uint handle);
        [DllImport("msi.dll", EntryPoint = "MsiDatabaseOpenViewW", CharSet = CharSet.Unicode)] internal static extern uint View(uint database, string query, out uint view);
        [DllImport("msi.dll", EntryPoint = "MsiViewExecute")] internal static extern uint Execute(uint view, uint record);
        [DllImport("msi.dll", EntryPoint = "MsiDatabaseCommit")] internal static extern uint Commit(uint database);
        [DllImport("msi.dll", EntryPoint = "MsiCloseHandle")] internal static extern uint Close(uint handle);
    }
}
