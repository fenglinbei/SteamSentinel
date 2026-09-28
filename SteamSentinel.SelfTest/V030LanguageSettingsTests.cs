using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Dialogs;
using SteamSentinel.App.Localization;
using SteamSentinel.App.Services;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030LanguageSettingsAsync(string root)
    {
        string directory = Path.Combine(root, "language-settings");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "user-a.json");
        Check("语言 首次启动自动且不创建文件", LanguageSettings.Load(path) == LanguagePreference.Automatic && !File.Exists(path));
        foreach (var (windows, expected) in new[] { ("zh-CN", "zh-Hans"), ("zh-TW", "zh-Hans"), ("en-GB", "en-US"), ("fr-FR", "en-US") })
            Check("语言 自动解析 " + windows, LanguageSettings.ResolveStartup([], path, CultureInfo.GetCultureInfo(windows)).Culture.Name == expected);
        foreach (LanguagePreference preference in Enum.GetValues<LanguagePreference>())
        {
            LanguageSettings.Save(path, preference);
            Check("语言 偏好往返 " + preference, LanguageSettings.Load(path) == preference && new FileInfo(path).Length <= 4096);
        }
        string original = await File.ReadAllTextAsync(path);
        foreach (string invalid in new[]
        {
            "", "{", "null", "[]", "{}", "{\"SchemaVersion\":\"1\",\"Language\":\"en\"}",
            "{\"SchemaVersion\":2,\"Language\":\"en\"}", "{\"SchemaVersion\":1,\"Language\":null}",
            "{\"SchemaVersion\":1,\"Language\":\"EN\"}", "{\"SchemaVersion\":1,\"Language\":\"fr\"}",
            "{\"SchemaVersion\":1,\"Language\":\"en\",\"Language\":\"zh-Hans\"}",
            "{\"SchemaVersion\":1,\"SchemaVersion\":1,\"Language\":\"en\"}",
            "{\"SchemaVersion\":1,\"Language\":\"en\",\"Unexpected\":true}",
            "{\"SchemaVersion\":999999999999,\"Language\":\"en\"}", new string(' ', 4097), "[[[[[[]]]]]]"
        })
        {
            await File.WriteAllTextAsync(path, invalid);
            LanguageStartupState fallback = LanguageSettings.ResolveStartup([], path, DisplayText.English);
            Check("语言 无效文件回退而不改写 " + invalid.Length, fallback.Culture == DisplayText.English &&
                fallback.SettingsError == LanguageSettingsError.Invalid && await File.ReadAllTextAsync(path) == invalid);
        }
        await File.WriteAllTextAsync(path, original.PadRight(4096));
        Check("语言 4096字节边界允许有效文档", LanguageSettings.Load(path) == LanguagePreference.English);
        await File.WriteAllTextAsync(path, original);
        bool rejected = false;
        try { LanguageSettings.Save(path, (LanguagePreference)99); } catch (ArgumentOutOfRangeException) { rejected = true; }
        Check("语言 未知枚举不覆盖旧设置", rejected && await File.ReadAllTextAsync(path) == original);
        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool failed = false;
            try { LanguageSettings.Save(path, LanguagePreference.SimplifiedChinese); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { failed = true; }
            Check("语言 保存冲突保留旧文件且清理本次临时文件", failed && File.ReadAllText(path) == original && Directory.GetFiles(directory, "*.tmp").Length == 0);
        }
        Check("语言 读取错误有明确回退原因", LanguageSettings.Read(directory).Error == LanguageSettingsError.Unreadable);
        LanguageSettings.Save(path, LanguagePreference.SimplifiedChinese);
        foreach (string[] arguments in new[]
        {
            new[] { "--ui-language", "en" }, new[] { "--administrator-window", "--ui-language", "auto" },
            new[] { "--administrator-window", "--ui-language", "en-US" }, new[] { "--administrator-window", "--ui-language", "en", "extra" },
            new[] { "--administrator-window", "--ui-language", "en --plan=C:\\inert" }, new[] { "--plan", "C:\\inert" }
        })
        {
            LanguageStartupState state = LanguageSettings.ResolveStartup(arguments, path, DisplayText.English);
            Check("语言 非白名单参数整体忽略 " + string.Join(" ", arguments), state.IgnoredArguments && !state.AdministratorWindowRequested && !state.InheritedLanguage && state.Culture == DisplayText.Chinese);
        }
        Check("语言 兼容旧管理员窗口标记", LanguageSettings.ResolveStartup([ElevationService.WindowArgument], path, DisplayText.English) is
        { AdministratorWindowRequested: true, InheritedLanguage: false, IgnoredArguments: false });
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            ProcessStartInfo start = ElevationService.CreateStartInfo();
            LanguageStartupState state = LanguageSettings.ResolveStartup(start.ArgumentList.ToArray(), path,
                culture == DisplayText.Chinese ? DisplayText.English : DisplayText.Chinese);
            Check("语言 管理员窗口继承当前实际语言 " + culture.Name, start.ArgumentList.Count == 3 && state.Culture == culture &&
                state.InheritedLanguage && state.AdministratorWindowRequested && !state.IgnoredArguments && LanguageSettings.Load(path) == LanguagePreference.SimplifiedChinese);
        }
        string otherPath = Path.Combine(directory, "user-b.json");
        LanguageSettings.Save(otherPath, LanguagePreference.English);
        LanguageStartupState otherAccount = LanguageSettings.ResolveStartup([ElevationService.WindowArgument, LanguageSettings.LanguageArgument, "zh-Hans"], otherPath, DisplayText.English);
        Check("语言 跨账户继承不改写对方偏好", otherAccount.Culture == DisplayText.Chinese && otherAccount.Preference == LanguagePreference.English && LanguageSettings.Load(otherPath) == LanguagePreference.English);
        await ProbeLanguageLaunchAsync(root, path, "en-US", "zh-Hans", [], "first-launch-zh");
        LanguageSettings.Save(path, LanguagePreference.English);
        await ProbeLanguageLaunchAsync(root, path, "zh-CN", "en-US", [], "next-launch-en");
        LanguageSettings.Save(path, LanguagePreference.Automatic);
        await ProbeLanguageLaunchAsync(root, path, "zh-TW", "zh-Hans", [], "automatic-zh");
        await ProbeLanguageLaunchAsync(root, path, "fr-FR", "en-US", [], "automatic-fallback");
        await ProbeLanguageLaunchAsync(root, otherPath, "en-US", "zh-Hans", [ElevationService.WindowArgument, LanguageSettings.LanguageArgument, "zh-Hans"], "other-account-inherited");
        ScanReport report = new()
        {
            ExecutionState = ScanExecutionState.Completed,
            Coverage = ScanCoverage.Partial,
            Findings = [new() { RuleId = "UI-INERT", Title = "原始标题", Evidence = "raw {0}", Sha256 = new string('A', 64) }]
        };
        byte[]? originalJson = null;
        string[]? originalEntries = null;
        foreach (var culture in new[] { DisplayText.Chinese, DisplayText.English })
        {
            using IDisposable scope = DisplayText.UseCulture(culture);
            string json = Path.Combine(directory, culture.Name + ".json"), markdown = Path.Combine(directory, culture.Name + ".md"), bundle = Path.Combine(directory, culture.Name + ".zip");
            await ReportExporter.ExportJsonAsync(report, json);
            await ReportExporter.ExportMarkdownAsync(report, markdown, culture);
            await CaseBundleExporter.ExportAsync(bundle, report, null, null, null, culture: culture);
            byte[] bytes = await File.ReadAllBytesAsync(json); originalJson ??= bytes;
            using ZipArchive zip = ZipFile.OpenRead(bundle);
            string[] entries = zip.Entries.Select(x => x.FullName).Order().ToArray(); originalEntries ??= entries;
            using StreamReader readme = new(zip.GetEntry("说明.txt")!.Open());
            using MemoryStream scan = new();
            using Stream scanEntry = zip.GetEntry("scan.json")!.Open();
            await scanEntry.CopyToAsync(scan);
            using JsonDocument parsed = JsonDocument.Parse(bytes);
            Check("语言导出 JSON与包内机器内容不变 " + culture.Name, bytes.SequenceEqual(originalJson) && scan.ToArray().SequenceEqual(bytes) &&
                entries.SequenceEqual(originalEntries) && !parsed.RootElement.TryGetProperty("DisplayLanguage", out _));
            string text = await File.ReadAllTextAsync(markdown), notice = DisplayText.Get("Report.OriginalTextNotice");
            Check("语言导出 保留原文并注明来源 " + culture.Name, text.Contains(notice) && text.Contains("原始标题") && readme.ReadToEnd().Contains(notice));
        }
        Check("语言导出 JSON跳过语言选择", !ExportLanguageDialog.RequiredForPath("inert.JSON") && ExportLanguageDialog.RequiredForPath("inert.md") && ExportLanguageDialog.RequiredForPath("inert.zip"));
    }

    private static async Task ProbeLanguageLaunchAsync(string root, string settingsPath, string windowsCulture, string expectedCulture, string[] arguments, string name)
    {
        string output = Path.Combine(root, name + ".json");
        ProcessStartInfo start = new(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "--language-startup-probe", output, settingsPath, windowsCulture }.Concat(arguments)) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(), stderr = process.StandardError.ReadToEndAsync();
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(25));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { if (!process.HasExited) process.Kill(entireProcessTree: true); throw; }
        string diagnostics = await stdout + await stderr;
        if (process.ExitCode != 0) throw new IOException("Language startup probe failed: " + diagnostics);
        using JsonDocument probe = JsonDocument.Parse(await File.ReadAllTextAsync(output));
        JsonElement data = probe.RootElement;
        Check("语言启动 新进程界面和后台保持一致 " + name, data.GetProperty("culture").GetString() == expectedCulture &&
            data.GetProperty("backgroundCulture").GetString() == expectedCulture && data.GetProperty("button").GetString() == (expectedCulture == "zh-Hans" ? "快速扫描" : "Quick scan") &&
            data.GetProperty("threadCulturesUnchanged").GetBoolean());
    }

    private static int RunLanguageStartupProbe(string output, string settingsPath, string windowsCulture, string[] arguments)
    {
        Exception? failure = null;
        Thread thread = new(() =>
        {
            SteamSentinel.App.App? app = null;
            try
            {
                CultureInfo oldCulture = CultureInfo.CurrentCulture, oldUi = CultureInfo.CurrentUICulture;
                app = new(); app.InitializeDisplayLanguage(arguments, settingsPath, CultureInfo.GetCultureInfo(windowsCulture));
                app.InitializeComponent(); app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                MainWindow window = new();
                Task<string> background;
                using (ExecutionContext.SuppressFlow()) background = Task.Run(() => DisplayText.Culture.Name);
                File.WriteAllText(output, JsonSerializer.Serialize(new
                {
                    culture = DisplayText.Culture.Name,
                    backgroundCulture = background.GetAwaiter().GetResult(),
                    button = ((Button)window.FindName("QuickScanButton")).Content,
                    title = window.Title,
                    app.AdministratorWindowRequested,
                    threadCulturesUnchanged = oldCulture.Equals(CultureInfo.CurrentCulture) && oldUi.Equals(CultureInfo.CurrentUICulture)
                }));
                CloseSummaryFixture(window);
            }
            catch (Exception ex) { failure = ex; }
            finally { app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); thread.Join();
        if (failure is null) return 0;
        Console.Error.WriteLine(failure); return 1;
    }

    private static async Task<int> RunV030LanguageSettingsAsync(string root)
    {
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Use a new language-test directory.");
        Directory.CreateDirectory(root);
        try { await TestV030LanguageSettingsAsync(root); await TestV017Async(root); }
        catch (Exception ex) { Failures.Add(ex.ToString()); }
        await JsonFile.WriteNewAsync(Path.Combine(root, "results.json"), new { passed = _passed, failed = Failures.Count, failures = Failures, completedAtUtc = DateTimeOffset.UtcNow });
        Console.WriteLine($"LANGUAGE_PASS={_passed};FAIL={Failures.Count}");
        foreach (string failure in Failures) Console.Error.WriteLine(failure);
        return Failures.Count == 0 ? 0 : 1;
    }
}
