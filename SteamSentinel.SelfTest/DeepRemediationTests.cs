using System.IO;
using System.Text.Json;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestDeepRemediationAsync(string root, RuleSet baseRules)
    {
        _ = baseRules;
        await TestDeepRandomPythonStealerHostAsync(root);
        await TestDeepPersistenceServiceKnownAsync(root);
        TestDeepFindingPriorityThreeTierReference();
    }

    private static async Task TestDeepRandomPythonStealerHostAsync(string root)
    {
        string workspace = Path.Combine(root, "deep-random-python-" + Guid.NewGuid().ToString("N"));
        string programs = Path.Combine(workspace, "Programs");
        Directory.CreateDirectory(programs);

        // 1. 高置信目录（10 + 45 + 15 + 20 + 15 = 105 -> 100）：同时保留目录级观察并额外产出可隔离 HOST 文件发现
        string highDir = Path.Combine(programs, "ab12cd34ef56gh78");
        Directory.CreateDirectory(Path.Combine(highDir, "pymem"));
        string hostExe = Path.Combine(highDir, "WindowsUpdatem.exe");
        const string inertHostPayload = "Inert random-python host fixture; plain text only, never executed.";
        await File.WriteAllTextAsync(hostExe, inertHostPayload);
        await File.WriteAllTextAsync(Path.Combine(highDir, "python311.dll"), "inert python placeholder");
        await File.WriteAllTextAsync(Path.Combine(highDir, "win32crypt.pyd"), "inert win32crypt placeholder");
        string expectedHostHash = await Hashing.Sha256FileAsync(hostExe);

        // 2. 中置信目录（score = 10 + 45 + 15 = 70 < 80）：仅保留目录级 ReviewOnly，绝不产出可隔离 HOST
        string mediumDir = Path.Combine(programs, "zx98cv76bn54ml32");
        Directory.CreateDirectory(mediumDir);
        await File.WriteAllTextAsync(Path.Combine(mediumDir, "WindowsUpdatem.exe"), "inert sub-threshold placeholder");
        await File.WriteAllTextAsync(Path.Combine(mediumDir, "python312.dll"), "inert python placeholder");

        ScanReport report = new();
        SystemScanner.ScanRandomProgramDirectoriesUnderRoot(programs, report, CancellationToken.None);

        Finding? highDirFinding = report.Findings.SingleOrDefault(f =>
            f.RuleId == "STRUCT-RANDOM-PYTHON-STEALER" && f.Target == highDir);
        Finding? hostFinding = report.Findings.SingleOrDefault(f =>
            f.RuleId == "STRUCT-RANDOM-PYTHON-STEALER-HOST" && f.Target == Path.GetFullPath(hostExe));
        Finding? mediumDirFinding = report.Findings.SingleOrDefault(f =>
            f.RuleId == "STRUCT-RANDOM-PYTHON-STEALER" && f.Target == mediumDir);
        bool noMediumHost = !report.Findings.Any(f =>
            f.RuleId == "STRUCT-RANDOM-PYTHON-STEALER-HOST" &&
            f.Target.StartsWith(mediumDir, StringComparison.OrdinalIgnoreCase));

        Check("深度规则 随机Python目录高置信同时保留目录复核与宿主文件可隔离项",
            highDirFinding is { CanRemediate: false, IsKnownMalware: false, Severity: FindingSeverity.Critical, Score: 100 } &&
            highDirFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
            hostFinding is
            {
                Category: FindingCategory.File,
                Severity: FindingSeverity.Critical,
                Score: 100,
                CanRemediate: true,
                IsKnownMalware: false
            } &&
            hostFinding.Sha256 == expectedHostHash &&
            hostFinding.TargetSha256 == expectedHostHash &&
            hostFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile]) &&
            FindingHandlingPresentation.Get(hostFinding).CanSelect &&
            !FindingHandlingPresentation.Get(highDirFinding).CanSelect);

        Check("深度规则 随机Python目录低于80分不产出可隔离宿主项",
            mediumDirFinding is { CanRemediate: false, Severity: FindingSeverity.High, Score: 70 } && noMediumHost);

        // 验证双语言展示无未注册资源键且无英文汉字泄露
        using (DisplayText.UseCulture(DisplayText.English))
        {
            Check("深度规则 随机Python宿主项复用既有双语资源键",
                hostFinding!.TitleText.Message is not null &&
                hostFinding.EvidenceText.Message is not null &&
                !hostFinding.TitleText.Display.Contains("Unrecognized display", StringComparison.Ordinal) &&
                !V030HasHan(hostFinding.TitleText.Display) &&
                !V030HasHan(hostFinding.EvidenceText.Display));
        }

        // 验证同目录存在目录级与文件级发现时，关联展开与计划构建零冲突
        RuleSet rules = new() { KnownPathTemplates = [programs] };
        SteamLayout layout = new();
        RelatedArtifactScanner relatedScanner = new(rules, LiveAssociationProbeMode.InertEmptyHost);
        RelatedArtifactExpansion expansion = await relatedScanner.ExpandLocalAsync(
            [hostFinding!], report, CancellationToken.None, RelatedArtifactScanner.MaximumVerificationBytes,
            requestExplicitFileTargets: false, layout, Path.Combine(workspace, "no-resident"));
        Check("深度规则 随机Python宿主项在同目录结构记录并存时顺畅完成关联展开",
            expansion.Findings.Any(f =>
                f.RuleId == "STRUCT-RANDOM-PYTHON-STEALER-HOST" &&
                f.CanRemediate &&
                f.Target == Path.GetFullPath(hostExe) &&
                f.Sha256 == expectedHostHash));

        RemediationPlan plan = await new RemediationPlanBuilder(rules, layout).BuildAsync(
            [hostFinding!], addKnownDomainBlock: false, allFindings: report.Findings);
        Check("深度规则 随机Python宿主项生成精确SHA256隔离计划且不触碰原文件",
            plan.Actions.Count == 1 &&
            plan.Actions[0].Type == RemediationActionType.QuarantineFile &&
            plan.Actions[0].Target == Path.GetFullPath(hostExe) &&
            plan.Actions[0].ExpectedSha256 == expectedHostHash &&
            File.Exists(hostExe));
    }

    private static async Task TestDeepPersistenceServiceKnownAsync(string root)
    {
        string workspace = Path.Combine(root, "deep-service-" + Guid.NewGuid().ToString("N"));
        string spacedDir = Path.Combine(workspace, "Sub Service Folder");
        Directory.CreateDirectory(spacedDir);

        string malwareExe = Path.Combine(spacedDir, "known-service-host.exe");
        await File.WriteAllTextAsync(malwareExe, "Inert known-hash service binary fixture; never executed.");
        string malwareHash = await Hashing.Sha256FileAsync(malwareExe);

        string benignExe = Path.Combine(spacedDir, "benign-helper.exe");
        await File.WriteAllTextAsync(benignExe, "Inert unmatched service binary fixture; never executed.");

        // 1. 命令行主程序提取边界覆盖（引号、空格路径、环境变量、未加引号带参、受保护系统程序拒绝、缺失文件拒绝）
        string quotedCmd = $"\"{malwareExe}\" --service --config \"C:\\ignored\\arg.exe\"";
        string unquotedCmd = $"{malwareExe} --daemon -k local";
        string systemCmd = $"\"{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe")}\" -k netsvcs";
        string envVarName = "STEAMSENTINEL_DEEP_SVC_DIR_" + Guid.NewGuid().ToString("N")[..8];
        Environment.SetEnvironmentVariable(envVarName, spacedDir);
        string envCmd = $"\"%{envVarName}%\\known-service-host.exe\" /autorun";
        try
        {
            Check("深度规则 服务ImagePath解析支持引号空格、环境变量与未加引号参数并拒绝系统保护目录",
                SystemScanner.TryExtractServiceExecutablePath(quotedCmd) == Path.GetFullPath(malwareExe) &&
                SystemScanner.TryExtractServiceExecutablePath(unquotedCmd) == Path.GetFullPath(malwareExe) &&
                SystemScanner.TryExtractServiceExecutablePath(envCmd) == Path.GetFullPath(malwareExe) &&
                SystemScanner.TryExtractServiceExecutablePath(@"\??\" + malwareExe) == Path.GetFullPath(malwareExe) &&
                SystemScanner.TryExtractServiceExecutablePath(systemCmd) is null &&
                SystemScanner.TryExtractServiceExecutablePath("\"unclosed-quote.exe") is null &&
                SystemScanner.TryExtractServiceExecutablePath(@"\\remote.invalid\share\svc.exe") is null &&
                SystemScanner.TryExtractServiceExecutablePath(Path.Combine(spacedDir, "missing.exe")) is null);

            RuleSet rules = new()
            {
                KnownProcessNames = ["benign-helper.exe", "known-service-host.exe", "substring-indicator.exe"],
                KnownPathTemplates = [spacedDir],
                KnownDomains = ["inert-service.example.invalid"],
                KnownHashes =
                [
                    new HashRule
                    {
                        Id = "TEST-KNOWN-SERVICE-HOST",
                        Label = "Inert service host hash fixture",
                        Sha256 = malwareHash,
                        Malware = true,
                        Severity = FindingSeverity.Critical
                    }
                ]
            };
            SystemScanner scanner = new(rules);
            ScanReport metricsReport = new();

            // 2. 命中已知恶意哈希 + Win32 服务类型：升级为 CanRemediate = true + DisableService
            Finding? upgraded = scanner.InspectServiceEntry("InertMalwareSvc", envCmd, serviceType: 0x10, startType: 2, metricsReport);
            Check("深度规则 服务ImagePath命中已知恶意哈希升级为可禁用服务且字段对齐Broker契约",
                upgraded is
                {
                    RuleId: "PERSISTENCE-SERVICE-KNOWN",
                    Category: FindingCategory.Persistence,
                    Severity: FindingSeverity.Critical,
                    Score: 95,
                    Target: "InertMalwareSvc",
                    Description: "InertMalwareSvc",
                    CanRemediate: true,
                    IsKnownMalware: true,
                    Sha256: null,
                    ConfigurationKind: "2"
                } &&
                upgraded.ConfigurationSnapshot == envCmd &&
                upgraded.RelatedFilePath == Path.GetFullPath(malwareExe) &&
                upgraded.RelatedFileSha256 == malwareHash &&
                upgraded.TargetSha256 == malwareHash &&
                upgraded.SuggestedActions.SequenceEqual([SuggestedActionKind.DisableService]) &&
                FindingHandlingPresentation.Get(upgraded).CanSelect &&
                metricsReport.Metrics.BytesHashed > 0);

            // 验证构建出的 RemediationPlan 与 BrokerBoundActions.ValidateAction 完全兼容，且与 PERSISTENCE-SERVICE-BOUND 去重无冲突
            SteamLayout layout = new();
            RemediationPlanBuilder builder = new(rules, layout);
            Finding boundPeer = new()
            {
                RuleId = "PERSISTENCE-SERVICE-BOUND",
                Category = FindingCategory.Persistence,
                Severity = FindingSeverity.Critical,
                Score = 100,
                Target = "InertMalwareSvc",
                ConfigurationKind = "2",
                ConfigurationSnapshot = envCmd,
                RelatedFilePath = Path.GetFullPath(malwareExe),
                RelatedFileSha256 = malwareHash,
                IsKnownMalware = true,
                CanRemediate = true,
                SuggestedActions = [SuggestedActionKind.DisableService]
            };
            RemediationPlan combinedPlan = await builder.BuildAsync(
                [upgraded!, boundPeer], addKnownDomainBlock: false, allFindings: [upgraded!, boundPeer], addAutomaticProgramBlock: false);
            RemediationAction disableAction = combinedPlan.Actions.Single(a => a.Type == RemediationActionType.DisableService);
            RemediationAction quarantineAction = combinedPlan.Actions.Single(a => a.Type == RemediationActionType.QuarantineFile);
            Check("深度规则 升级服务计划与PERSISTENCE-SERVICE-BOUND无损去重并联动隔离宿主文件",
                disableAction.Target == "InertMalwareSvc" &&
                disableAction.RelatedFilePath == Path.GetFullPath(malwareExe) &&
                disableAction.RelatedFileSha256 == malwareHash &&
                disableAction.ConfigurationKind == "2" &&
                disableAction.ConfigurationSnapshot == envCmd &&
                quarantineAction.Target == Path.GetFullPath(malwareExe) &&
                quarantineAction.ExpectedSha256 == malwareHash &&
                File.Exists(malwareExe));

            // 3. 仅子串命中但哈希未命中已知恶意规则 / 文件不存在 / 内核驱动类型：严格保持 ReviewOnly
            Finding? substringUnmatched = scanner.InspectServiceEntry(
                "InertSubstringSvc", $"\"{benignExe}\" --svc", serviceType: 0x10, startType: 2);
            Finding? substringMissing = scanner.InspectServiceEntry(
                "InertMissingSvc", $"\"{Path.Combine(spacedDir, "substring-indicator.exe")}\" --svc", serviceType: 0x10, startType: 2);
            Finding? driverBlocked = scanner.InspectServiceEntry(
                "InertDriverSvc", quotedCmd, serviceType: 0x01, startType: 2);
            Finding? bootStartBlocked = scanner.InspectServiceEntry(
                "InertBootSvc", quotedCmd, serviceType: 0x10, startType: 1);

            Check("深度规则 服务仅子串命中、缺失文件或驱动类型严格保持ReviewOnly不可自动处置",
                new[] { substringUnmatched, substringMissing, driverBlocked, bootStartBlocked }.All(item =>
                    item is { RuleId: "PERSISTENCE-SERVICE-KNOWN", CanRemediate: false, IsKnownMalware: false, Severity: FindingSeverity.High, Score: 75 } &&
                    item.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) &&
                    !FindingHandlingPresentation.Get(item).CanSelect));
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, null);
        }
    }

    private static void TestDeepFindingPriorityThreeTierReference()
    {
        const string root = @"C:\SteamSentinel-Inert-ThreeTier-Fixtures\";
        static bool IsSingleReference(Finding finding) =>
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [finding] }).Contains(finding.Id);

        // 1. 防护与纯信息规则进入折叠组
        Finding hostsBlocked = new()
        {
            Id = "ref-hosts-blocked",
            RuleId = "NETWORK-C2-BLOCKED",
            Category = FindingCategory.Network,
            Severity = FindingSeverity.Information,
            Target = root + @"drivers\etc\hosts",
            SuggestedActions = [SuggestedActionKind.None]
        };
        Finding syntheticHostsBlocked = new()
        {
            Id = "ref-hosts-empty-target",
            RuleId = "NETWORK-C2-BLOCKED",
            Category = FindingCategory.Network,
            Severity = FindingSeverity.Information,
            SuggestedActions = [SuggestedActionKind.None]
        };
        Finding millennium = new()
        {
            Id = "ref-millennium",
            RuleId = "STEAM-MOD-MILLENNIUM",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Information,
            Score = 5,
            Target = root + "Steam\\millennium",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding workshopMeta = new()
        {
            Id = "ref-workshop-meta",
            RuleId = "WORKSHOP-PROJECT-METADATA",
            Category = FindingCategory.WallpaperEngine,
            Severity = FindingSeverity.Medium,
            Score = 35,
            Target = root + @"workshop\431960\10001",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding signatureObs = new()
        {
            Id = "ref-host-sig",
            RuleId = "ASSOCIATION-HOST-SIGNATURE",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Information,
            Target = root + "signed-host.exe",
            SuggestedActions = [SuggestedActionKind.None]
        };
        Finding benignMsi = new()
        {
            Id = "ref-benign-msi",
            RuleId = "INSTALLER-STRUCTURE",
            Category = FindingCategory.Archive,
            Severity = FindingSeverity.Information,
            Score = 5,
            ReasonCode = null,
            Target = root + "setup.msi",
            SuggestedActions = [SuggestedActionKind.None]
        };
        Finding docStrings = new()
        {
            Id = "ref-doc-strings",
            RuleId = "CONTENT-SUSPICIOUS-STRINGS",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Information,
            Score = 40,
            Target = root + "README.md",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };

        Check("三层分组 7类防护与低噪信息规则在无同路径冲突时纳入信息与参考折叠组",
            new[] { hostsBlocked, syntheticHostsBlocked, millennium, workshopMeta, signatureObs, benignMsi, docStrings }
                .All(IsSingleReference));

        // 2. 安装包与可疑字符串的严重度/信号门禁
        Finding suspiciousMsi = new()
        {
            Id = "pri-suspicious-msi",
            RuleId = "INSTALLER-STRUCTURE",
            Category = FindingCategory.Archive,
            Severity = FindingSeverity.Medium,
            Score = 40,
            ReasonCode = "ScriptTokenCooccurrenceOnly",
            Target = root + "suspicious.msi",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding lowStrings = new()
        {
            Id = "pri-low-strings",
            RuleId = "CONTENT-SUSPICIOUS-STRINGS",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Low,
            Score = 20,
            Target = root + "script.txt",
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding coverageGap = new()
        {
            Id = "pri-coverage",
            RuleId = "TRUST-PROXY-COVERAGE",
            Category = FindingCategory.Coverage,
            Severity = FindingSeverity.Information,
            Target = "Proxy.Check"
        };
        Check("三层分组 带信号MSI、非Info字符串及Coverage缺口保持主表或覆盖率页绝不折叠",
            !IsSingleReference(suspiciousMsi) && !IsSingleReference(lowStrings) && !IsSingleReference(coverageGap));

        // 3. 本地环回代理 vs PAC URL / 远端代理 / 关联证书或高危网络发现
        Check("三层分组 环回代理目标识别精确放行本机端口并拦截PAC与远端地址",
            FindingPriorityPresentation.IsLoopbackProxyTarget("127.0.0.1:7897") &&
            FindingPriorityPresentation.IsLoopbackProxyTarget("localhost:7890") &&
            FindingPriorityPresentation.IsLoopbackProxyTarget("[::1]:10808") &&
            FindingPriorityPresentation.IsLoopbackProxyTarget("http=127.0.0.1:7890;https=127.0.0.1:7890;socks=localhost:7891") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("http://inert.invalid/proxy.pac") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("http://127.0.0.1:7890/proxy.pac") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("https://127.0.0.1:7890") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("192.168.1.1:7890") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("http=127.0.0.1:7890;https=203.0.113.5:8080") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("localhost.evil.example:7890") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("127.0.0.1:0") &&
            !FindingPriorityPresentation.IsLoopbackProxyTarget("127.0.0.1:70000"));

        static Finding ProxyFinding(string id, string target) => new()
        {
            Id = id,
            RuleId = "NETWORK-PROXY-PRESENT",
            Category = FindingCategory.Network,
            Severity = FindingSeverity.Information,
            Score = 5,
            Target = target,
            HandlingReason = FindingHandlingReason.InsufficientEvidence,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };

        Finding clashProxy = ProxyFinding("proxy-clash", "127.0.0.1:7897");
        Finding pacProxy = ProxyFinding("proxy-pac", "http://inert.invalid/proxy.pac");
        Finding loopbackPacProxy = ProxyFinding("proxy-loopback-pac", "http://127.0.0.1:7890/proxy.pac");
        Finding remoteProxy = ProxyFinding("proxy-remote", "203.0.113.10:8080");
        Check("三层分组 纯本地环回代理默认折叠而PAC与远端代理保留主表人工核实",
            IsSingleReference(clashProxy) &&
            !IsSingleReference(pacProxy) &&
            !IsSingleReference(loopbackPacProxy) &&
            !IsSingleReference(remoteProxy));

        // 同报告含无关本地文件威胁时，纯环回代理仍折叠；含 CERTIFICATE-NAME-REVIEW 或高危网络发现时不折叠
        Finding unrelatedFileMalware = new()
        {
            Id = "file-malware",
            RuleId = "INERT-FILE-MALWARE",
            Category = FindingCategory.File,
            Severity = FindingSeverity.Critical,
            IsKnownMalware = true,
            CanRemediate = true,
            Target = root + "downloads\\bad.exe",
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        Finding certReview = new()
        {
            Id = "cert-review",
            RuleId = "CERTIFICATE-NAME-REVIEW",
            Category = FindingCategory.Certificate,
            Severity = FindingSeverity.Information,
            Target = "CN=help.steampowered.com",
            HandlingReason = FindingHandlingReason.InsufficientEvidence,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding hostsRedirect = new()
        {
            Id = "hosts-redirect",
            RuleId = "NETWORK-C2-HOSTS-REDIRECT",
            Category = FindingCategory.Network,
            Severity = FindingSeverity.High,
            Score = 70,
            Target = hostsBlocked.Target,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.BlockKnownDomains]
        };

        Check("三层分组 无关文件威胁不影响纯本地环回代理折叠",
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [unrelatedFileMalware, clashProxy] })
                .SetEquals([clashProxy.Id]));
        Check("三层分组 存在可疑证书复核项时本地环回代理提升回主表",
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [clashProxy, certReview] }).Count == 0);
        Check("三层分组 存在高危网络劫持时本地环回代理与同路径hosts阻断提示均不折叠",
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [clashProxy, hostsBlocked, hostsRedirect] }).Count == 0);

        // 验证同物理路径 blocked 组防线对新增折叠项同样生效
        Finding docCoverageGap = new()
        {
            Id = "doc-gap",
            RuleId = "SCAN-PARTIAL",
            Category = FindingCategory.Coverage,
            Target = docStrings.Target
        };
        Check("三层分组 同物理路径存在覆盖缺口时文档提示不折叠",
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [docStrings, docCoverageGap] }).Count == 0);

        Finding steamCfgPresent = new()
        {
            Id = "ref-steam-cfg",
            RuleId = "STEAM-CFG-PRESENT",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Low,
            Score = 15,
            Target = root + @"Steam\steam.cfg",
            CanRemediate = false,
            SuggestedActions = [SuggestedActionKind.ReviewOnly]
        };
        Finding steamCfgControl = new()
        {
            Id = "pri-steam-cfg-control",
            RuleId = "STEAM-CFG-CONTROL-SETTING",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.Medium,
            Score = 45,
            Target = steamCfgPresent.Target,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };
        Finding steamCfgPair = new()
        {
            Id = "pri-steam-cfg-pair",
            RuleId = "STEAM-CFG-UPDATE-SUPPRESSION-PAIR",
            Category = FindingCategory.Steam,
            Severity = FindingSeverity.High,
            Score = 85,
            Target = steamCfgPresent.Target,
            CanRemediate = true,
            SuggestedActions = [SuggestedActionKind.RepairSteamConfiguration]
        };
        Finding steamCfgGap = new()
        {
            Id = "steam-cfg-gap",
            RuleId = "SCAN-PARTIAL",
            Category = FindingCategory.Coverage,
            Target = steamCfgPresent.Target
        };
        Check("三层分组 无敏感项steam.cfg默认折叠而控制项、禁更对及同路径覆盖缺口保留主表",
            IsSingleReference(steamCfgPresent) &&
            !IsSingleReference(steamCfgControl) &&
            !IsSingleReference(steamCfgPair) &&
            FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [steamCfgPresent, steamCfgGap] }).Count == 0);

        string snapshotBefore = JsonSerializer.Serialize(clashProxy, JsonFile.Options);
        _ = FindingPriorityPresentation.ReferenceFindingIds(new ScanReport { Findings = [clashProxy] });
        Check("三层分组 扩展分类不改动原Finding序列化字节",
            JsonSerializer.Serialize(clashProxy, JsonFile.Options) == snapshotBefore);
    }
}
