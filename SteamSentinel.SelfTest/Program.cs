using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static class Program
{
    private static readonly List<string> Failures = [];
    private static int _passed;
    private static int _skipped;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0) return await RunUtilityAsync(args);

        string root = Path.Combine(Path.GetTempPath(), "SteamSentinel-SelfTest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            RuleSet rules = RuleLoader.LoadEmbedded();
            Check("规则集载入", rules.KnownHashes.Count >= 14 && rules.KnownDomains.Contains("luminovastella.top"));
            TestServiceAppCoverage(rules);

            await TestFileTypesAsync(root);
            await TestJsonFileSynchronizationContextAsync(root);
            await TestWriteNewAndDirectoryFingerprintAsync(root);
            TestSecurityValidation();
            await TestContentScannerAsync(root, rules);
            await TestDefaultWallpaperSuppressionAsync(root, rules);
            await TestSteamTamperScannerAsync(root, rules);
            await TestEncryptedArchiveAsync(root, rules);
            await TestWorkerProtocolAsync(root);
            await TestRestrictedWorkerClientAsync(root);
            await TestPlanBuilderAsync(root, rules);
            await TestBoundBrokerPlanAsync();
            await TestSecureFileLeaseAsync(root);
            await TestReportExportAsync(root, rules);
            Check("Steam 进程门禁不误判 SteamSentinel", MainWindow.IsSteamClientProcessName("steam") &&
                                                     MainWindow.IsSteamClientProcessName("steamwebhelper") &&
                                                     !MainWindow.IsSteamClientProcessName("SteamSentinel"));
            TestDisplayLabels();
            TestSteamDiscovery();
            await TestSystemScannerReadOnlyAsync(rules);

            Console.WriteLine();
            Console.WriteLine($"通过：{_passed}；失败：{Failures.Count}；跳过：{_skipped}");
            foreach (string failure in Failures) Console.WriteLine("FAIL: " + failure);
            return Failures.Count == 0 ? 0 : 1;
        }
        finally
        {
            string full = Path.GetFullPath(root);
            string temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
            if (full.StartsWith(temp + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                Directory.Exists(full) && !Validation.ContainsReparsePoint(full))
            {
                Directory.Delete(full, recursive: true);
            }
        }
    }

    private static async Task TestFileTypesAsync(string root)
    {
        string disguised = Path.Combine(root, "video.mp4");
        await File.WriteAllBytesAsync(disguised, [0x4D, 0x5A, 0, 0, 0, 0]);
        FileTypeResult type = await FileTypeDetector.DetectAsync(disguised);
        Check("MZ 改名 MP4", type.Type == DetectedFileType.PortableExecutable && type.ExtensionMismatch);

        string validMp4 = Path.Combine(root, "valid.mp4");
        await File.WriteAllBytesAsync(validMp4, CreateMinimalMp4());
        Mp4InspectionResult valid = await Mp4Inspector.InspectAsync(validMp4);
        Check("最小 MP4 结构", valid.IsStructurallyValid && valid.TrailingBytes == 0);

        string zip = Path.Combine(root, "tail.zip");
        CreateZip(zip, archive =>
        {
            ZipArchiveEntry entry = archive.CreateEntry("readme.txt");
            using StreamWriter writer = new(entry.Open(), Encoding.UTF8);
            writer.Write("harmless");
        });
        string polyglot = Path.Combine(root, "polyglot.mp4");
        await using (FileStream output = File.Create(polyglot))
        {
            await output.WriteAsync(CreateMinimalMp4());
            await using FileStream input = File.OpenRead(zip);
            await input.CopyToAsync(output);
        }
        Mp4InspectionResult overlay = await Mp4Inspector.InspectAsync(polyglot);
        Check("MP4 尾随 ZIP", overlay.TrailingBytes > 0 && overlay.EmbeddedType?.Contains("ZIP", StringComparison.Ordinal) == true);
    }

    private static void TestServiceAppCoverage(RuleSet rules)
    {
        const string hash = "B0F17D38174E22DCB175663A7B904C3C532BDC9AA93531F988DE3F19DDEE2B7A";
        Check("ServiceApp 精确恶意哈希规则", rules.KnownHashes.Any(rule =>
            rule.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase) && rule.Malware));
        Check("ServiceApp 进程候选名称", rules.KnownProcessNames.Contains("ServiceApp.exe", StringComparer.OrdinalIgnoreCase));
        Check("Wallpaper 多库进程路径纳入哈希", SystemScanner.IsWallpaperWorkshopContentPath(
                  @"L:\SteamLibrary\steamapps\workshop\content\431960\3437694514\vid_720p\renamed.exe") &&
              !SystemScanner.IsWallpaperWorkshopContentPath(
                  @"L:\SteamLibrary\steamapps\workshop\content\431961\3437694514\vid_720p\renamed.exe"));

        SystemScanner scanner = new(rules);
        Check("ServiceApp Run 项确认为可处置链", scanner.IsConfirmedRunIndicator(
            "ServiceAppMscopiAuto",
            "\"L:\\SteamLibrary\\steamapps\\workshop\\content\\431960\\3437694514\\vid_720p\\ServiceApp.exe\""));
    }

    private static async Task TestJsonFileSynchronizationContextAsync(string root)
    {
        string path = Path.Combine(root, "synchronization-context.json");
        JsonProbe expected = new() { Payload = new string('x', 2 * 1024 * 1024) };
        await JsonFile.WriteAtomicAsync(path, expected);

        bool completedWithoutPumping = await Task.Run(() =>
        {
            NonPumpingSynchronizationContext context = new();
            SynchronizationContext? original = SynchronizationContext.Current;
            SynchronizationContext.SetSynchronizationContext(context);
            try
            {
                Task<JsonProbe> readTask = JsonFile.ReadAsync<JsonProbe>(path);
                if (!readTask.Wait(TimeSpan.FromSeconds(3))) return false;
                return readTask.Status == TaskStatus.RanToCompletion &&
                       readTask.Result.Payload.Length == expected.Payload.Length &&
                       context.PostCount == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(original);
            }
        });

        Check("JSON 异步读取不捕获调用方同步上下文", completedWithoutPumping);
    }

    private static async Task TestWriteNewAndDirectoryFingerprintAsync(string root)
    {
        string newOnly = Path.Combine(root, "new-only.json");
        await JsonFile.WriteNewAsync(newOnly, new JsonProbe { Payload = "first" });
        bool overwriteRejected = false;
        try { await JsonFile.WriteNewAsync(newOnly, new JsonProbe { Payload = "second" }); }
        catch (IOException) { overwriteRejected = true; }
        JsonProbe retained = await JsonFile.ReadAsync<JsonProbe>(newOnly);
        Check("受保护结果只新建不覆盖", overwriteRejected && retained.Payload == "first");

        string directory = Path.Combine(root, "fingerprint");
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, "item.txt");
        await File.WriteAllTextAsync(file, "first");
        string before = await DirectoryFingerprint.ComputeAsync(directory);
        await File.WriteAllTextAsync(file, "second");
        string after = await DirectoryFingerprint.ComputeAsync(directory);
        Check("目录指纹绑定内容变化", Validation.IsHexSha256(before) && before != after);
    }

    private static void TestSecurityValidation()
    {
        Check("计划任务名称拒绝后缀冒充与路径穿越",
            Validation.TryNormalizeScheduledTaskName(@"\ServiceApp360GuardLogon", out string exact) &&
            exact == @"\ServiceApp360GuardLogon" &&
            Validation.TryNormalizeScheduledTaskName(@"\Folder\ServiceApp360GuardLogon", out string nested) &&
            nested != exact &&
            !Validation.TryNormalizeScheduledTaskName(@"\..\ServiceApp360GuardLogon", out _));
        Check("开发目录不会误启用管理员处置", !InstallationSecurity.Evaluate().IsProtected);
    }

    private static async Task TestContentScannerAsync(string root, RuleSet rules)
    {
        string scanRoot = Path.Combine(root, "content");
        Directory.CreateDirectory(scanRoot);
        string traversalArchive = Path.Combine(scanRoot, "renamed.mp4");
        CreateZip(traversalArchive, archive =>
        {
            ZipArchiveEntry suspicious = archive.CreateEntry("../payload.cmd");
            using (StreamWriter writer = new(suspicious.Open(), Encoding.UTF8))
            {
                writer.Write("@echo off\r\nrem SteamKey20260310\r\n");
            }
            ZipArchiveEntry normal = archive.CreateEntry("wallpaper.jpg");
            using Stream normalStream = normal.Open();
            normalStream.Write([0xFF, 0xD8, 0xFF, 0xD9]);
        });

        ScanReport report = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        using ContentScanner scanner = new(rules);
        await scanner.ScanRootAsync(scanRoot, report, new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true,
            MaximumArchiveDepth = 4,
            MaximumCompressionRatio = 500
        }, new NullPasswordProvider());

        Check("改后缀 ZIP 检测", report.Findings.Any(f => f.RuleId == "CONTENT-EXTENSION-MISMATCH"));
        Check("压缩包路径穿越检测", report.Findings.Any(f => f.RuleId == "ARCHIVE-PATH-TRAVERSAL"));
        Check("嵌套条目家族字符串", report.Findings.Any(f => f.RuleId == "CONTENT-SUSPICIOUS-STRINGS" && f.Score >= 60));

        string ratioArchive = Path.Combine(scanRoot, "ratio.zip");
        CreateZip(ratioArchive, archive =>
        {
            ZipArchiveEntry zeros = archive.CreateEntry("zeros.bin", CompressionLevel.SmallestSize);
            using Stream stream = zeros.Open();
            stream.Write(new byte[2 * 1024 * 1024]);
        });
        ScanReport ratioReport = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        using ContentScanner ratioScanner = new(rules);
        await ratioScanner.ScanRootAsync(ratioArchive, ratioReport, new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true,
            MaximumCompressionRatio = 2
        }, new NullPasswordProvider());
        Check("解压炸弹压缩比限制", ratioReport.Coverage == ScanCoverage.Partial &&
                                  ratioReport.Findings.Any(f => f.RuleId == "ARCHIVE-RATIO-LIMIT"));

        string quickFile = Path.Combine(scanRoot, "small-unknown.bin");
        await File.WriteAllTextAsync(quickFile, "harmless quick hash test");
        ScanReport quickReport = new() { Mode = ScanMode.Quick, RuleSetVersion = rules.Version };
        using ContentScanner quickScanner = new(rules);
        await quickScanner.ScanRootAsync(quickFile, quickReport, new ScanOptions
        {
            Mode = ScanMode.Quick,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = false,
            UseAmsi = false,
            HashEveryFile = false
        }, new NullPasswordProvider());
        Check("快速模式小文件哈希", quickReport.Metrics.BytesHashed == new FileInfo(quickFile).Length);
    }

    private static async Task TestEncryptedArchiveAsync(string root, RuleSet rules)
    {
        string? archiveTool = FindArchiveTool(out bool useRar);
        if (archiveTool is null)
        {
            Skip("加密包密码交互（未安装 7-Zip/WinRAR 测试工具）");
            return;
        }

        string encryptedRoot = Path.Combine(root, "encrypted");
        Directory.CreateDirectory(encryptedRoot);
        string payload = Path.Combine(encryptedRoot, "note.txt");
        await File.WriteAllTextAsync(payload, "harmless encrypted test");
        string archive = Path.Combine(encryptedRoot, useRar ? "protected.rar" : "protected.zip");
        ProcessStartInfo startInfo = new()
        {
            FileName = archiveTool,
            WorkingDirectory = encryptedRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        string[] arguments = useRar
            ? ["a", "-idq", "-ep", "-ptestpass", archive, payload]
            : ["a", "-tzip", "-mem=AES256", "-ptestpass", archive, payload];
        foreach (string arg in arguments) startInfo.ArgumentList.Add(arg);
        using (Process process = Process.Start(startInfo)!)
        {
            await process.WaitForExitAsync();
            if (process.ExitCode != 0)
            {
                Skip("加密包密码交互（测试包创建失败）");
                return;
            }
        }
        File.Delete(payload);

        TestPasswordProvider provider = new("testpass");
        ScanReport report = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        using ContentScanner scanner = new(rules);
        await scanner.ScanRootAsync(archive, report, new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true
        }, provider);
        Check("加密包请求密码", provider.RequestCount > 0);
        Check("正确密码完整扫描", report.Coverage == ScanCoverage.Complete && report.Metrics.ArchiveEntriesVisited > 0);

        ScanReport skippedReport = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        using ContentScanner skippedScanner = new(rules);
        await skippedScanner.ScanRootAsync(archive, skippedReport, new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true
        }, new NullPasswordProvider());
        Check("拒绝密码标记未完整", skippedReport.Coverage == ScanCoverage.Partial &&
                                  skippedReport.Findings.Any(f => f.RuleId == "ARCHIVE-ENCRYPTED-NOT-SCANNED"));
    }

    private static async Task TestDefaultWallpaperSuppressionAsync(string root, RuleSet rules)
    {
        string directory = Path.Combine(root, "defaultprojects-fixture");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "legitimate-engine.exe");
        await File.WriteAllBytesAsync(executable, [0x4D, 0x5A, 0, 0, 0, 0]);
        ScanReport report = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        using ContentScanner scanner = new(rules);
        await scanner.ScanRootAsync(directory, report, new ScanOptions
        {
            Mode = ScanMode.Full,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = false,
            UseAmsi = false,
            HashEveryFile = true
        }, new NullPasswordProvider(), workshopId: "local:defaultprojects", projectType: "trusted-default");
        Check("内置 defaultprojects 不按可执行类型误报", report.Findings.All(finding => finding.RuleId != "WORKSHOP-EXECUTABLE-CONTENT"));
    }

    private static async Task TestSteamTamperScannerAsync(string root, RuleSet rules)
    {
        string steamRoot = Path.Combine(root, "steam-tamper-fixture");
        string steamUi = Path.Combine(steamRoot, "steamui");
        Directory.CreateDirectory(steamUi);
        await File.WriteAllTextAsync(Path.Combine(steamRoot, "steam.cfg"), "BootStrapperInhibitAll=enable\nBootStrapperForceSelfUpdate=disable\n");
        const string script = "BMustShowSupportAlertDialog(){return!0;}BHasActiveSupportAlerts(){return!0;}OnGameActionUserRequest(e){SteamClient.URL.ExecuteSteamURL(\"steam://open/supportalert\");return;switch(e){}}let _h=\"https://luminovastella.top/steamhelper?d=76561198700358719&a=\",_s=\"https://luminovastella.top/steamhelper.html?u=x&d=76561198700358719&a=\";return({SupportMessages:_s,HelpAppPage:_h,HelpFrontPage:_h})[e];jsx(\"div\",{style:{display:\"none\"},className:styles.URLBar,children:[m?.bIsSecure,loc(\"#Browser_NotSecure\")]});";
        await File.WriteAllTextAsync(Path.Combine(steamUi, "chunk.js"), script);
        SteamLayout layout = new();
        layout.SteamRoots.Add(steamRoot);
        ScanReport report = new() { Mode = ScanMode.Full, RuleSetVersion = rules.Version };
        await new SteamSecurityScanner(rules).ScanAsync(layout, report);
        Check("Steam 禁更配置成对识别", report.Findings.Any(finding => finding.RuleId == "STEAM-CFG-UPDATE-SUPPRESSION-PAIR" && finding.CanRemediate));
        Finding? tamper = report.Findings.FirstOrDefault(finding => finding.RuleId == "STEAM-UI-SEMANTIC-TAMPERING");
        Check("Steam UI 假红信语义识别", tamper is { Severity: FindingSeverity.High, CanRemediate: true } && tamper.Description.Contains("固定为真", StringComparison.Ordinal));
        Check("Steam UI 第三方客服路由识别", tamper?.Description.Contains("luminovastella.top", StringComparison.Ordinal) == true);
        Check("Steam UI 隐藏地址栏识别", tamper?.Description.Contains("display:none", StringComparison.Ordinal) == true);
    }

    private static async Task TestPlanBuilderAsync(string root, RuleSet rules)
    {
        string file = Path.Combine(root, "candidate.bin");
        await File.WriteAllTextAsync(file, "harmless remediation-plan test");
        Finding finding = new()
        {
            Category = FindingCategory.File,
            Severity = FindingSeverity.High,
            Score = 70,
            Title = "synthetic",
            Target = file,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RemediationPlan plan = await new RemediationPlanBuilder(rules).BuildAsync([finding], false);
        RemediationAction? action = plan.Actions.SingleOrDefault();
        Check("处置计划精确哈希", action is { Type: RemediationActionType.QuarantineFile } &&
                               Validation.IsHexSha256(action.ExpectedSha256) && Path.IsPathFullyQualified(action.Target));

        string executable = Path.Combine(root, "ServiceApp.exe");
        await File.WriteAllTextAsync(executable, "synthetic process ordering fixture");
        string executableHash = await Hashing.Sha256FileAsync(executable);
        Finding[] processFindings = new[] { 101, 202 }.Select(processId => new Finding
        {
            Category = FindingCategory.Process,
            Severity = FindingSeverity.Critical,
            Score = 100,
            Title = "synthetic running malware",
            Target = executable,
            Sha256 = executableHash,
            ProcessId = processId,
            IsKnownMalware = true,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.StopProcess, SuggestedActionKind.QuarantineFile]
        }).ToArray();
        RemediationPlan multiProcessPlan = await new RemediationPlanBuilder(rules).BuildAsync(processFindings, false);
        int quarantineIndex = multiProcessPlan.Actions.FindIndex(item => item.Type == RemediationActionType.QuarantineFile);
        int lastStopIndex = multiProcessPlan.Actions.FindLastIndex(item => item.Type == RemediationActionType.StopProcess);
        Check("同一文件多进程全部先停止再隔离", multiProcessPlan.Actions.Count(item => item.Type == RemediationActionType.StopProcess) == 2 &&
                                               multiProcessPlan.Actions.Count(item => item.Type == RemediationActionType.QuarantineFile) == 1 &&
                                               lastStopIndex >= 0 && quarantineIndex > lastStopIndex);
    }

    private static async Task TestBoundBrokerPlanAsync()
    {
        Directory.CreateDirectory(AppPaths.PlansRoot);
        RemediationPlan plan = new()
        {
            Actions =
            {
                new RemediationAction
                {
                    Type = RemediationActionType.RestoreSecurityControls,
                    DisplayName = "绑定测试",
                    Target = "Windows Security"
                }
            }
        };
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        try
        {
            await JsonFile.WriteAtomicAsync(planPath, plan);
            string hash = await Hashing.Sha256FileExclusiveAsync(planPath);
            RemediationPlan loaded = await BrokerRequestReader.ReadAsync(planPath, hash);
            Check("Broker 计划哈希与请求者 SID 绑定", loaded.PlanId == plan.PlanId);

            await File.AppendAllTextAsync(planPath, " ");
            bool rejected = false;
            try { await BrokerRequestReader.ReadAsync(planPath, hash); }
            catch (InvalidDataException) { rejected = true; }
            Check("Broker 拒绝 UAC 前后被改写的计划", rejected);

            await File.WriteAllBytesAsync(planPath, new byte[(1024 * 1024) + 1]);
            string oversizedHash = await Hashing.Sha256FileExclusiveAsync(planPath);
            bool oversizedRejected = false;
            try { await BrokerRequestReader.ReadAsync(planPath, oversizedHash); }
            catch (InvalidDataException) { oversizedRejected = true; }
            Check("Broker 按锁定句柄拒绝超大计划", oversizedRejected);
        }
        finally
        {
            try { File.Delete(planPath); } catch { }
        }
    }

    private static async Task TestSecureFileLeaseAsync(string root)
    {
        string directory = Path.Combine(root, "secure-file-lease");
        Directory.CreateDirectory(directory);
        string source = Path.Combine(directory, "source.bin");
        string destination = Path.Combine(directory, "destination.quarantined");
        await File.WriteAllTextAsync(source, "harmless handle-bound quarantine test", Encoding.UTF8);
        string expected = await Hashing.Sha256FileExclusiveAsync(source);
        await using (SecureFileLease lease = SecureFileLease.Open(source))
        {
            string current = await lease.ComputeSha256Async(CancellationToken.None);
            await lease.CopyToAsync(destination, current, CancellationToken.None);
            lease.DeleteOnClose();
        }
        string copied = await Hashing.Sha256FileExclusiveAsync(destination);
        Check("句柄绑定隔离复制、复核与删除", !File.Exists(source) && copied == expected);
    }

    private static async Task TestWorkerProtocolAsync(string root)
    {
        string solutionRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        string workerBin = Path.Combine(solutionRoot, "SteamSentinel.ArchiveWorker", "bin");
        string? workerPath = Directory.Exists(workerBin)
            ? Directory.EnumerateFiles(workerBin, "SteamSentinel.ArchiveWorker.exe", SearchOption.AllDirectories)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault()
            : null;
        if (workerPath is null)
        {
            Skip("隔离扫描工作进程协议（未找到构建产物）");
            return;
        }

        string encrypted = Directory.Exists(Path.Combine(root, "encrypted"))
            ? Directory.EnumerateFiles(Path.Combine(root, "encrypted"), "protected.*").FirstOrDefault() ?? string.Empty
            : string.Empty;
        string target = File.Exists(encrypted) ? encrypted : Path.Combine(root, "content", "renamed.mp4");
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true,
            CustomRoots = [target]
        };
        ProcessStartInfo startInfo = new()
        {
            FileName = workerPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardInputEncoding = Encoding.UTF8,
            StandardOutputEncoding = Encoding.UTF8
        };
        using Process worker = Process.Start(startInfo)!;
        System.Text.Json.JsonSerializerOptions compact = new(JsonFile.Options) { WriteIndented = false };
        string start = System.Text.Json.JsonSerializer.Serialize(
            new WorkerMessage { Type = WorkerMessageTypes.Start, Options = options }, compact);
        await worker.StandardInput.WriteLineAsync(start);
        await worker.StandardInput.FlushAsync();
        ScanReport? report = null;
        bool passwordRequested = false;
        string? workerFailure = null;
        while (true)
        {
            string? line = await worker.StandardOutput.ReadLineAsync();
            if (line is null) break;
            WorkerMessage? message = System.Text.Json.JsonSerializer.Deserialize<WorkerMessage>(line, JsonFile.Options);
            if (message?.Type == WorkerMessageTypes.PasswordRequest && message.PasswordRequest is not null)
            {
                passwordRequested = true;
                string response = System.Text.Json.JsonSerializer.Serialize(new WorkerMessage
                {
                    Type = WorkerMessageTypes.PasswordResponse,
                    PasswordResponse = new ArchivePasswordResponse(message.PasswordRequest.RequestId, false, "testpass", false)
                }, compact);
                await worker.StandardInput.WriteLineAsync(response);
                await worker.StandardInput.FlushAsync();
            }
            else if (message?.Type == WorkerMessageTypes.Completed)
            {
                report = message.Report;
                break;
            }
            else if (message?.Type == WorkerMessageTypes.Failed)
            {
                workerFailure = message.Error;
                break;
            }
        }
        await worker.WaitForExitAsync();
        string workerError = await worker.StandardError.ReadToEndAsync();
        if (report is null)
        {
            Console.WriteLine($"WORKER DEBUG: exit={worker.ExitCode}; protocol={workerFailure}; stderr={workerError}");
        }
        Check("隔离扫描工作进程协议", report is not null && worker.ExitCode == 0);
        if (File.Exists(encrypted)) Check("工作进程密码往返", passwordRequested && report?.Coverage == ScanCoverage.Complete);
    }

    private static async Task TestRestrictedWorkerClientAsync(string root)
    {
        string solutionRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        string workerBin = Path.Combine(solutionRoot, "SteamSentinel.ArchiveWorker", "bin");
        string? workerPath = Directory.Exists(workerBin)
            ? Directory.EnumerateFiles(workerBin, "SteamSentinel.ArchiveWorker.exe", SearchOption.AllDirectories)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault()
            : null;
        if (workerPath is null)
        {
            Skip("Low Integrity + Job Object 工作进程（未找到构建产物）");
            return;
        }

        string target = Path.Combine(root, "content", "renamed.mp4");
        ScanOptions options = new()
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true,
            CustomRoots = [target]
        };
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
        try
        {
            ScanReport report = await new ArchiveWorkerClient(workerPath).RunAsync(
                options,
                (request, _) => Task.FromResult(new ArchivePasswordResponse(request.RequestId, true, null, false)),
                null,
                timeout.Token);
            Check("Low Integrity + Job Object 工作进程", report.CompletedAtUtc is not null);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"SANDBOX DEBUG: {ex.GetType().Name}: {ex.Message}");
            Check("Low Integrity + Job Object 工作进程", false);
        }
    }

    private static async Task TestReportExportAsync(string root, RuleSet rules)
    {
        ScanReport report = new() { Mode = ScanMode.Custom, RuleSetVersion = rules.Version, CompletedAtUtc = DateTimeOffset.UtcNow };
        report.Findings.Add(new Finding
        {
            RuleId = "TEST",
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Information,
            Title = "测试",
            Target = "C:\\redacted",
            Evidence = "无敏感信息"
        });
        string json = Path.Combine(root, "report.json");
        string markdown = Path.Combine(root, "report.md");
        await ReportExporter.ExportJsonAsync(report, json);
        await ReportExporter.ExportMarkdownAsync(report, markdown);
        Check("JSON/Markdown 报告导出", File.Exists(json) && File.Exists(markdown) && new FileInfo(markdown).Length > 100);
    }

    private static void TestSteamDiscovery()
    {
        SteamLayout layout = SteamLocator.Discover();
        Check("Steam 多库发现不抛异常", layout.SteamRoots.Count >= 0 && layout.LibraryRoots.Count >= 0);
    }

    private static async Task TestSystemScannerReadOnlyAsync(RuleSet rules)
    {
        ScanReport report = await new ScanCoordinator(rules).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Quick,
            IncludeSystem = true,
            IncludeSteam = true,
            IncludeWorkshop = false,
            InspectArchives = false,
            UseAmsi = false,
            HashEveryFile = false
        });

        Check("系统与 Steam 只读扫描", report.CompletedAtUtc is not null && report.Metrics.ProcessesVisited > 0);
    }

    private static void TestDisplayLabels()
    {
        Check("发现分类使用中文展示", Enum.GetValues<FindingCategory>().All(value =>
            !ReportExporter.CategoryLabel(value).Equals(value.ToString(), StringComparison.Ordinal)));
        Check("扫描覆盖状态使用中文展示", Enum.GetValues<ScanCoverage>().All(value =>
            !ReportExporter.CoverageLabel(value).Equals(value.ToString(), StringComparison.Ordinal)));
        Check("处置动作使用中文展示", Enum.GetValues<RemediationActionType>().All(value =>
            !ReportExporter.ActionLabel(value).Equals(value.ToString(), StringComparison.Ordinal)));
    }

    private static async Task<int> RunUtilityAsync(string[] args)
    {
        switch (args[0])
        {
            case "--prepare-broker-smoke":
                return await PrepareBrokerSmokeAsync();
            case "--prepare-broker-rollback" when args.Length == 2:
                return await PrepareBrokerRollbackAsync(args[1]);
            case "--prepare-broker-delete" when args.Length == 2:
                return await PrepareBrokerDeleteAsync(args[1]);
            case "--scan-path" when args.Length == 2:
                return await ScanPathUtilityAsync(args[1]);
            case "--verify-cleanup-broker-smoke" when args.Length == 4:
                return await VerifyAndCleanupBrokerSmokeAsync(args[1], args[2], args[3]);
            default:
                Console.Error.WriteLine("未知的 SelfTest 工具参数。");
                return 2;
        }
    }

    private static async Task<int> PrepareBrokerSmokeAsync()
    {
        string token = Guid.NewGuid().ToString("N");
        string smokeRoot = Path.Combine(AppPaths.UserStateRoot, "BrokerSmoke");
        Directory.CreateDirectory(smokeRoot);
        Directory.CreateDirectory(AppPaths.PlansRoot);
        string target = Path.Combine(smokeRoot, $"harmless-{token}.txt");
        await File.WriteAllTextAsync(target, $"SteamSentinel harmless broker smoke test {token}", Encoding.UTF8);
        string hash = await Hashing.Sha256FileAsync(target);
        RemediationPlan plan = new()
        {
            Actions =
            {
                new RemediationAction
                {
                    Type = RemediationActionType.QuarantineFile,
                    DisplayName = "无害文件隔离集成测试",
                    Target = target,
                    ExpectedSha256 = hash
                }
            }
        };
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        string resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        await JsonFile.WriteAtomicAsync(planPath, plan);
        string planHash = await Hashing.Sha256FileExclusiveAsync(planPath);
        Console.WriteLine($"PLAN={planPath}");
        Console.WriteLine($"PLAN_SHA256={planHash}");
        Console.WriteLine($"RESULT={resultPath}");
        Console.WriteLine($"TARGET={target}");
        return 0;
    }

    private static async Task<int> PrepareBrokerRollbackAsync(string quarantineResultPath)
    {
        RemediationRunResult quarantineResult = await JsonFile.ReadAsync<RemediationRunResult>(quarantineResultPath);
        if (!quarantineResult.Success || quarantineResult.ManifestPath is null || !File.Exists(quarantineResult.ManifestPath))
            throw new InvalidDataException("隔离测试结果无效，不能创建回滚计划。");
        string incident = quarantineResult.IncidentId.ToString("D");
        RemediationPlan plan = new()
        {
            Actions =
            {
                new RemediationAction
                {
                    Type = RemediationActionType.RollbackIncident,
                    DisplayName = "无害文件回滚集成测试",
                    Target = incident,
                    IncidentId = incident
                }
            }
        };
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        string resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        await JsonFile.WriteAtomicAsync(planPath, plan);
        string planHash = await Hashing.Sha256FileExclusiveAsync(planPath);
        Console.WriteLine($"PLAN={planPath}");
        Console.WriteLine($"PLAN_SHA256={planHash}");
        Console.WriteLine($"RESULT={resultPath}");
        Console.WriteLine($"INCIDENT={incident}");
        return 0;
    }

    private static async Task<int> VerifyAndCleanupBrokerSmokeAsync(
        string quarantineResultPath,
        string rollbackResultPath,
        string target)
    {
        RemediationRunResult quarantineResult = await JsonFile.ReadAsync<RemediationRunResult>(quarantineResultPath);
        RemediationRunResult rollbackResult = await JsonFile.ReadAsync<RemediationRunResult>(rollbackResultPath);
        if (!quarantineResult.Success || !rollbackResult.Success || quarantineResult.ManifestPath is null)
            throw new InvalidDataException("Broker 隔离或回滚结果失败。");
        QuarantineManifest manifest = await JsonFile.ReadAsync<QuarantineManifest>(quarantineResult.ManifestPath);
        string smokeRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(AppPaths.UserStateRoot, "BrokerSmoke")));
        string fullTarget = Path.GetFullPath(target);
        if (!fullTarget.StartsWith(smokeRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            manifest.Records.Count != 1 || !manifest.Records[0].RolledBack ||
            !Path.GetFullPath(manifest.Records[0].OriginalTarget).Equals(fullTarget, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(fullTarget))
        {
            throw new InvalidDataException("Broker 回滚后的目标或清单状态不符合预期。");
        }
        string content = await File.ReadAllTextAsync(fullTarget);
        if (!content.StartsWith("SteamSentinel harmless broker smoke test ", StringComparison.Ordinal))
            throw new InvalidDataException("测试文件内容不符合安全清理标记。");
        if (manifest.Records[0].QuarantinedPath is { } quarantined && File.Exists(quarantined))
            throw new InvalidDataException("回滚后隔离副本仍存在，拒绝清理测试状态。");

        File.Delete(fullTarget);
        Console.WriteLine("BROKER_ROLLBACK_PASS");
        return 0;
    }

    private static async Task<int> PrepareBrokerDeleteAsync(string quarantineResultPath)
    {
        RemediationRunResult quarantineResult = await JsonFile.ReadAsync<RemediationRunResult>(quarantineResultPath);
        if (!quarantineResult.Success || quarantineResult.ManifestPath is null || !File.Exists(quarantineResult.ManifestPath))
            throw new InvalidDataException("隔离测试结果无效，不能创建删除计划。");
        QuarantineManifest manifest = await JsonFile.ReadAsync<QuarantineManifest>(quarantineResult.ManifestPath);
        if (manifest.Records.Count == 0 || manifest.Records.Any(record => !record.RolledBack))
            throw new InvalidDataException("仅允许为已完整回滚的测试事件创建即时删除计划。");
        string incident = quarantineResult.IncidentId.ToString("D");
        RemediationPlan plan = new()
        {
            Actions =
            {
                new RemediationAction
                {
                    Type = RemediationActionType.DeleteIncident,
                    DisplayName = "删除已回滚的无害测试事件",
                    Target = incident,
                    IncidentId = incident
                }
            }
        };
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{plan.PlanId:N}.json");
        string resultPath = Path.Combine(AppPaths.ResultsRoot, $"result-{plan.PlanId:N}.json");
        await JsonFile.WriteAtomicAsync(planPath, plan);
        string planHash = await Hashing.Sha256FileExclusiveAsync(planPath);
        Console.WriteLine($"PLAN={planPath}");
        Console.WriteLine($"PLAN_SHA256={planHash}");
        Console.WriteLine($"RESULT={resultPath}");
        Console.WriteLine($"INCIDENT={incident}");
        return 0;
    }

    private static async Task<int> ScanPathUtilityAsync(string path)
    {
        ScanReport report = await new ScanCoordinator().RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            InspectArchives = true,
            UseAmsi = false,
            HashEveryFile = true,
            CustomRoots = [Path.GetFullPath(path)]
        });
        Console.WriteLine($"COVERAGE={report.Coverage}");
        Console.WriteLine($"FINDINGS={report.Findings.Count}");
        foreach (Finding finding in report.Findings)
            Console.WriteLine($"{finding.RuleId}|{finding.Severity}|{finding.Score}|{finding.Sha256}|{finding.Title}");
        return report.Findings.Any(finding => finding.IsKnownMalware && finding.Score == 100) ? 0 : 1;
    }

    private static byte[] CreateMinimalMp4()
    {
        using MemoryStream stream = new();
        WriteBigEndian(stream, 24);
        stream.Write("ftyp"u8);
        stream.Write("isom"u8);
        WriteBigEndian(stream, 0x200);
        stream.Write("isom"u8);
        stream.Write("iso2"u8);
        WriteBigEndian(stream, 8);
        stream.Write("free"u8);
        return stream.ToArray();
    }

    private static void WriteBigEndian(Stream stream, int value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void CreateZip(string path, Action<ZipArchive> writer)
    {
        using FileStream stream = File.Create(path);
        using ZipArchive archive = new(stream, ZipArchiveMode.Create);
        writer(archive);
    }

    private static string? FindArchiveTool(out bool useRar)
    {
        string[] sevenZipCandidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip", "7z.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "7-Zip", "7z.exe")
        ];
        string? sevenZip = sevenZipCandidates.FirstOrDefault(File.Exists);
        if (sevenZip is not null)
        {
            useRar = false;
            return sevenZip;
        }

        string[] rarCandidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinRAR", "Rar.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinRAR", "Rar.exe")
        ];
        useRar = true;
        return rarCandidates.FirstOrDefault(File.Exists);
    }

    private static void Check(string name, bool condition)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine("PASS: " + name);
        }
        else
        {
            Failures.Add(name);
            Console.WriteLine("FAIL: " + name);
        }
    }

    private static void Skip(string name)
    {
        _skipped++;
        Console.WriteLine("SKIP: " + name);
    }

    private sealed class TestPasswordProvider(string password) : IArchivePasswordProvider
    {
        public int RequestCount { get; private set; }
        public Task<ArchivePasswordResponse> RequestPasswordAsync(ArchivePasswordRequest request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(new ArchivePasswordResponse(request.RequestId, false, password, false));
        }
    }

    private sealed class JsonProbe
    {
        public string Payload { get; init; } = string.Empty;
    }

    private sealed class NonPumpingSynchronizationContext : SynchronizationContext
    {
        private int _postCount;
        public int PostCount => _postCount;

        public override void Post(SendOrPostCallback d, object? state) =>
            Interlocked.Increment(ref _postCount);
    }
}
