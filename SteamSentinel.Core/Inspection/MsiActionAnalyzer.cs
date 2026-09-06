using System.Text;
using System.Text.RegularExpressions;

namespace SteamSentinel.Core.Inspection;

/// <summary>Symbolic MSI declarations only: no formatting, condition, install or execution APIs.</summary>
internal static class MsiActionAnalyzer
{
    internal const int MaximumActions = 512;
    internal const int MaximumEvidenceLines = 64;
    internal const int MaximumEvidenceCharacters = 16384;
    private const int MaximumResolvedCharacters = 8192;
    private const int MaximumReferenceDepth = 16;
    private static readonly HashSet<string> StandardDirectories = new(StringComparer.Ordinal)
    {
        "TARGETDIR", "AdminToolsFolder", "AppDataFolder", "CommonAppDataFolder", "CommonFilesFolder", "CommonFiles64Folder",
        "DesktopFolder", "FavoritesFolder", "FontsFolder", "LocalAppDataFolder", "MyPicturesFolder", "PersonalFolder",
        "ProgramFilesFolder", "ProgramFiles64Folder", "ProgramMenuFolder", "SendToFolder", "StartMenuFolder", "StartupFolder",
        "SystemFolder", "System64Folder", "TempFolder", "TemplateFolder", "WindowsFolder", "WindowsVolume"
    };
    private static readonly Regex Identifier = new("^[A-Za-z_][A-Za-z0-9_.]*$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    internal static MsiActionAnalysis Analyze(MsiInspection data, CancellationToken token = default)
    {
        MsiActionAnalysis result = new() { ActionCount = data.Actions.Count };
        int evidenceCharacters = 0;
        int resolutionSteps = 0;
        bool evidenceTruncated = false;
        Dictionary<string, MsiProperty> properties = Unique(data.Properties, p => p.Name);
        Dictionary<string, MsiCustomAction> actions = Unique(data.Actions, a => a.Action);
        Dictionary<string, MsiDirectory> directories = Unique(data.Directories, d => d.Id);
        Dictionary<string, MsiComponent> components = Unique(data.Components, c => c.Id);
        Dictionary<string, MsiFile> files = Unique(data.Files, f => f.Id);
        ILookup<string, MsiSequence> sequences = data.Sequences.ToLookup(s => s.Action, StringComparer.Ordinal);
        ILookup<string, MsiCustomAction> assignments = data.Actions.Where(a => BasicType(a.Type) == 51).ToLookup(a => a.Source, StringComparer.Ordinal);

        foreach (MsiTableRead table in data.Tables)
        {
            Evidence($"表 {table.Table}: {table.State}，读取 {table.Rows} 行" + (table.Detail.Length == 0 ? "" : "；" + table.Detail));
            if (table.State is MsiReadState.Failed or MsiReadState.LimitReached or MsiReadState.NotChecked)
                Gap($"{table.Table}: {table.State}，{table.Detail}");
        }
        if (data.Actions.Count > MaximumActions) Gap($"自定义动作分析达到 {MaximumActions} 项上限，余下 {data.Actions.Count - MaximumActions} 项未分析");
        foreach (MsiCustomAction action in data.Actions.Take(MaximumActions))
        {
            token.ThrowIfCancellationRequested();
            int basic = BasicType(action.Type);
            string type = DescribeType(action.Type);
            MsiSequence[] schedules = sequences[action.Action].ToArray();
            string placement = schedules.Length == 0 ? "未列入已读取的 UI/Execute 序列" : string.Join("；", schedules.Take(8).Select(s =>
                $"{s.Table}={SequenceLabel(s.Sequence)}, 条件={Display(s.Condition.Length == 0 ? "<无条件>" : s.Condition, 180)}"));
            Evidence($"动作 {action.Action}: {type}；{placement}");
            if (schedules.Length > 8) Gap($"动作 {action.Action} 的序列关联超过显示上限");
            if (!Supported(basic)) Gap($"动作 {action.Action} 的类型 {action.Type?.ToString() ?? "NULL"} 不受静态动作语义支持");

            // Preserve the established rule on one literal action payload, including Type 51
            // property text. Names, unrelated actions and sequence labels never become code.
            if (TargetIsPayload(basic))
            {
                foreach (string signal in ScriptSignals.Analyze(action.Target))
                    AddUnique(result.ContentSignals, $"{Display(action.Action, 80)}: {signal}" + (basic == 51 ? "（属性文本，未证明执行）" : "（单一动作文本）"));
            }
            Evidence($"动作 {action.Action} 引用: {SourceReference(action, null)}；Target={Display(RedactedTarget(action), 640)}");
            if (basic == 51 && action.Source.Length == 0) Gap($"动作 {action.Action} 的 Type 51 目标属性为空");

            foreach (MsiSequence schedule in schedules.Take(8))
            {
                if (schedule.Sequence is null or <= 0 || IsFalse(schedule.Condition)) continue;
                if (!Supported(basic) || basic is 19 or 35 or 51) continue;
                if ((action.Type.GetValueOrDefault() & 0x400) != 0)
                { Gap($"动作 {action.Action} 为延迟/回滚/提交执行；运行时 CustomActionData 和属性上下文未解析"); continue; }
                if (!TableComplete("CustomAction") || !TableComplete(schedule.Table))
                { Gap($"动作 {action.Action} 的动作表或序列表未完整读取，不能确认属性顺序"); continue; }
                if (!actions.ContainsKey(action.Action)) { Gap($"动作 {action.Action} 标识重复，不能建立唯一引用"); continue; }
                Resolution payload = Payload(action, schedule);
                Evidence($"动作 {action.Action} @ {schedule.Table}/{schedule.Sequence} 解析: {((action.Type.GetValueOrDefault() & 0x2000) != 0 ? "[隐藏的 Target]" : payload.Text)}；完整={payload.Complete}；{Timing(schedule)}");
                if (payload.Complete)
                    foreach (string signal in ScriptSignals.Analyze(payload.Text))
                        AddUnique(result.LinkedSignals, $"{Display(action.Action, 80)}@{schedule.Table}/{schedule.Sequence}: {signal}（声明关联，运行条件未执行验证）");
            }
        }

        foreach (MsiFile file in data.Files.Take(96))
        {
            Resolution path = FilePath(file.Id, new HashSet<string>(StringComparer.Ordinal), 0);
            MsiMedia? media = file.Sequence is > 0 ? data.Media.Where(m => m.LastSequence >= file.Sequence).OrderBy(m => m.LastSequence).FirstOrDefault() : null;
            Evidence($"文件 {file.Id} → Component {file.Component} → {path.Text}；File.Sequence={file.Sequence?.ToString() ?? "NULL"}；Media={media?.DiskId?.ToString() ?? "未关联"} {media?.Cabinet ?? ""}（不证明 CAB 成员身份）");
        }
        if (data.Files.Count > 96) Gap($"文件落点摘要只展示前 96 项，其余 {data.Files.Count - 96} 项未展开显示");
        foreach (MsiRegistry row in data.Registry.Take(16))
        {
            string root = row.Root switch { 0 => "HKCR", 1 => "HKCU", 2 => "HKLM", 3 => "HKU", -1 => "HKCU/HKLM（依安装上下文）", _ => "未知根" };
            Evidence($"注册表声明 {row.Id}: {root}\\{row.Key}，Name={row.Name}，Value={Display(row.Value, 256)}；{ComponentReference(row.Component)}");
        }
        foreach (MsiShortcut row in data.Shortcuts.Take(16))
            Evidence($"快捷方式声明 {row.Id}: {DirectoryPath(row.Directory, new(StringComparer.Ordinal), 0).Text}\\{LongName(row.Name)}；Target={row.Target}；Arguments={Display(row.Arguments, 256)}；WkDir 属性={row.WorkingDirectory}；{ComponentReference(row.Component)}；通告快捷方式的 Feature 目标未解析");
        foreach (MsiServiceInstall row in data.Services.Take(16))
            Evidence($"服务安装声明 {row.Id}: Name={row.Name}，Type={row.ServiceType}，StartType={row.StartType}，Arguments={Display(row.Arguments, 256)}；{ComponentReference(row.Component)}；服务密码字段未读取");
        foreach (MsiServiceControl row in data.ServiceControls.Take(16))
            Evidence($"服务控制声明 {row.Id}: Name={row.Name}，Event={row.Event}，Arguments={Display(row.Arguments, 256)}；{ComponentReference(row.Component)}");
        foreach ((string table, int count) in new[] { ("Registry", data.Registry.Count), ("Shortcut", data.Shortcuts.Count), ("ServiceInstall", data.Services.Count), ("ServiceControl", data.ServiceControls.Count) })
            if (count > 16) Gap($"{table} 摘要只展示前 16 项，余下 {count - 16} 项未展开显示");
        foreach (MsiMedia media in data.Media.Where(m => m.Cabinet.Length > 0 && !m.Cabinet.StartsWith('#')).Take(16))
            Gap("安装包引用外部 CAB，未访问或下载：" + Display(media.Cabinet, 180));
        Evidence("以上为只读安装声明；未验证实际安装、条件求值或程序运行后设置。表内未见证书/PAC 不能排除运行时设置。");
        return result;

        string ComponentReference(string id)
        {
            if (!components.TryGetValue(id, out MsiComponent? component)) { Gap("缺失或重复 Component 引用：" + Display(id, 100)); return "Component=" + id + "（未解析）"; }
            string key = files.ContainsKey(component.KeyPath) ? FilePath(component.KeyPath, new(StringComparer.Ordinal), 0).Text : component.KeyPath + "（非已解析文件 KeyPath）";
            return $"Component={id}，Directory={DirectoryPath(component.Directory, new(StringComparer.Ordinal), 0).Text}，KeyPath={key}，Condition={Display(component.Condition, 100)}";
        }
        Resolution SourceReference(MsiCustomAction action, MsiSequence? schedule)
        {
            int basic = BasicType(action.Type);
            if (basic is 1 or 2 or 5 or 6)
            {
                bool found = data.BinaryNames.Contains(action.Source);
                if (!found) Gap($"动作 {action.Action} 缺失 Binary 引用：{Display(action.Source, 100)}");
                return new("Binary:" + action.Source + (found ? "（内容由内嵌成员扫描独立检查）" : "（未解析）"), found);
            }
            if (basic is 17 or 18 or 21 or 22) return FilePath(action.Source, new(StringComparer.Ordinal), 0);
            if (basic is 34 or 35)
            {
                Resolution directory = DirectoryPath(action.Source, new(StringComparer.Ordinal), 0);
                return new((basic == 34 ? "工作目录=" : "设置 Directory=") + directory.Text, directory.Complete);
            }
            if (basic is 50 or 53 or 54)
                return schedule is null ? new("Property:" + action.Source + "（需同序列上下文）", false) : Property(action.Source, schedule, new(StringComparer.Ordinal), 0);
            if (basic == 51) return new("设置 Property:" + action.Source, true);
            return new(basic is 37 or 38 ? "内联脚本" : "Source:" + action.Source, basic is 37 or 38 or 19);
        }
        Resolution Payload(MsiCustomAction action, MsiSequence schedule)
        {
            int basic = BasicType(action.Type);
            Resolution source = SourceReference(action, schedule);
            // Inline and property script bodies are not MSI formatted command strings.
            if (basic is 37 or 38) return new(action.Target, true);
            if (basic is 53 or 54) return source;
            Resolution target = Format(action.Target, schedule, new(StringComparer.Ordinal), 0);
            if (basic is 18 or 50) return Combine(source, target);
            if (basic == 34) return new(target.Text, source.Complete && target.Complete);
            // Binary/File script and DLL bodies live in separately scanned members.
            // The Target entrypoint/argument text is not their executable body.
            if (basic is 1 or 5 or 6 or 17 or 21 or 22) return new(source.Text + "; Target=" + target.Text, false);
            if (basic == 2) return new(target.Text, source.Complete && target.Complete);
            return new(target.Text, false);
        }
        Resolution Property(string name, MsiSequence schedule, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[属性解析预算耗尽]", false);
            if (SensitiveProperty(name)) return Unknown("敏感属性值不进入语义摘要：" + name, "[敏感属性]");
            if (depth >= MaximumReferenceDepth || !visiting.Add("P:" + name)) return Unknown("属性引用循环或深度达到上限：" + name, "[" + name + "]");
            try
            {
                if (!TableComplete("Property", allowAbsent: true)) return Unknown("Property 表未完整读取：" + name, "[" + name + "]");
                var setters = assignments[name].Where(a => a.Action != schedule.Action).SelectMany(a => sequences[a.Action].Where(s => s.Table == schedule.Table && s.Sequence is > 0 && s.Sequence <= schedule.Sequence)
                    .Select(s => (Action: a, Schedule: s))).Where(s => !IsFalse(s.Schedule.Condition)).ToArray();
                if (setters.Length > 0)
                {
                    int? latest = setters.Max(s => s.Schedule.Sequence);
                    var candidates = setters.Where(s => s.Schedule.Sequence == latest).ToArray();
                    if (latest == schedule.Sequence || candidates.Length != 1 || !IsUnconditional(candidates[0].Schedule.Condition))
                        return Unknown("属性赋值顺序或条件未确定：" + name, "[" + name + "]");
                    MsiCustomAction setter = candidates[0].Action;
                    if ((setter.Type.GetValueOrDefault() & 0x700) != 0)
                        return Unknown("属性赋值的执行调度或脚本上下文未确定：" + name, "[" + name + "]");
                    // Type51 evaluates at its own earlier position, so repeated assignments can
                    // refer to an earlier value of the same property without a false self-cycle.
                    HashSet<string> earlier = new(visiting, StringComparer.Ordinal);
                    earlier.Remove("P:" + name);
                    return Format(setter.Target, candidates[0].Schedule, earlier, depth + 1);
                }
                if (!properties.TryGetValue(name, out MsiProperty? property)) return Unknown("属性不存在、重复或运行时值未知：" + name, "[" + name + "]");
                // Values in Property are literal. MSI does not recursively expand their brackets.
                return new(property.Value, true);
            }
            finally { visiting.Remove("P:" + name); }
        }
        Resolution Format(string text, MsiSequence schedule, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[格式解析预算耗尽]", false);
            if (depth >= MaximumReferenceDepth) return Unknown("Formatted 引用深度达到上限", Display(text, 256));
            StringBuilder output = new(); bool complete = true;
            for (int i = 0; i < text.Length; i++)
            {
                if ((i & 127) == 0) token.ThrowIfCancellationRequested();
                if (text[i] != '[') output.Append(text[i]);
                else
                {
                    int end = text.IndexOf(']', i + 1);
                    if (end < 0) return Unknown("Formatted 括号不完整", Display(text, 256));
                    string reference = text[(i + 1)..end]; Resolution value;
                    if (reference.StartsWith('\\') && reference.Length == 2) value = new(reference[1].ToString(), true);
                    else if (reference == "~") value = new("<NUL>", false);
                    else if (reference.StartsWith('#') && Identifier.IsMatch(reference[1..])) value = FilePath(reference[1..], new(StringComparer.Ordinal), 0);
                    else if (reference.StartsWith('$') && Identifier.IsMatch(reference[1..]) && components.TryGetValue(reference[1..], out MsiComponent? component)) value = DirectoryPath(component.Directory, new(StringComparer.Ordinal), 0);
                    else if (Identifier.IsMatch(reference)) value = Property(reference, schedule, visiting, depth + 1);
                    else value = Unknown("不支持或未解析的 Formatted 引用：" + Display(reference, 100), "[" + reference + "]");
                    output.Append(value.Text); complete &= value.Complete; i = end;
                }
                if (output.Length > MaximumResolvedCharacters) return Unknown("Formatted 解析文本达到上限", output.ToString(0, 256));
            }
            return new(output.ToString(), complete);
        }
        Resolution FilePath(string id, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[#" + id + "]", false);
            if (!files.TryGetValue(id, out MsiFile? file)) return Unknown("缺失或重复 File 引用：" + id, "[#" + id + "]");
            if (!components.TryGetValue(file.Component, out MsiComponent? component)) return Unknown("文件缺失或重复 Component 引用：" + file.Component, "[#" + id + "]");
            Resolution parent = DirectoryPath(component.Directory, visiting, depth + 1);
            string name = LongName(file.Name);
            if (!SafeSegment(name)) return Unknown("文件名不是受支持的单一名称：" + id, "[#" + id + "]");
            return new(parent.Text + "\\" + name, parent.Complete);
        }
        Resolution DirectoryPath(string id, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[" + id + "]", false);
            if (depth >= MaximumReferenceDepth || !visiting.Add(id)) return Unknown("Directory 引用循环或深度达到上限：" + id, "[" + id + "]");
            try
            {
                if (!directories.TryGetValue(id, out MsiDirectory? directory)) return Unknown("缺失或重复 Directory 引用：" + id, "[" + id + "]");
                if (StandardDirectories.Contains(id)) return new("[" + id + "]", true);
                string segment = LongName(directory.DefaultDir.Split(':')[0]);
                if (directory.Parent.Length == 0) return new("[" + id + "]", true);
                Resolution parent = DirectoryPath(directory.Parent, visiting, depth + 1);
                if (segment == ".") return parent;
                if (!SafeSegment(segment)) return Unknown("Directory 目标名称未解析：" + id, "[" + id + "]");
                return new(parent.Text + "\\" + segment, parent.Complete);
            }
            finally { visiting.Remove(id); }
        }
        string Timing(MsiSequence schedule)
        {
            MsiSequence? finalize = sequences["InstallFinalize"].FirstOrDefault(s => s.Table == schedule.Table && s.Sequence > 0);
            return finalize is not null && schedule.Sequence > finalize.Sequence ? "声明位于 InstallFinalize 之后" : "声明顺序不证明实际执行";
        }
        bool TableComplete(string table, bool allowAbsent = false) => data.Tables.FirstOrDefault(t => t.Table == table)?.State is MsiReadState.Complete ||
            (allowAbsent && data.Tables.FirstOrDefault(t => t.Table == table)?.State is MsiReadState.Absent);
        bool SpendResolution()
        {
            token.ThrowIfCancellationRequested();
            if (++resolutionSteps <= 32768) return true;
            Gap("安装语义引用解析达到 32768 步上限，余下引用保持未解析");
            return false;
        }
        Resolution Unknown(string gap, string symbolic) { Gap(gap); return new(symbolic, false); }
        void Evidence(string value)
        {
            string safe = Display(value, 1024);
            if (result.Evidence.Count >= MaximumEvidenceLines || evidenceCharacters + safe.Length > MaximumEvidenceCharacters)
            { if (!evidenceTruncated) { evidenceTruncated = true; Gap("安装语义证据摘要达到行数或字符上限，详细表记录未传输"); } return; }
            result.Evidence.Add(safe); evidenceCharacters += safe.Length;
        }
        void Gap(string value)
        {
            string safe = Display(value, 256);
            if (result.CoverageGaps.Contains(safe, StringComparer.Ordinal)) return;
            if (result.CoverageGaps.Count < 63) result.CoverageGaps.Add(safe);
            else if (result.CoverageGaps.Count == 63) result.CoverageGaps.Add("安装语义缺口摘要达到 64 项上限，后续对象未逐项传输");
        }
    }

    private static Dictionary<string, T> Unique<T>(IEnumerable<T> values, Func<T, string> key) => values.GroupBy(key, StringComparer.Ordinal).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.Single(), StringComparer.Ordinal);
    private static void AddUnique(List<string> values, string value) { if (values.Count < 32 && !values.Contains(value, StringComparer.Ordinal)) values.Add(value); }
    private static int BasicType(int? type) => type is >= 0 and <= 65535 ? type.Value & 0x3f : -1;
    private static bool Supported(int basic) => basic is 1 or 2 or 5 or 6 or 17 or 18 or 19 or 21 or 22 or 34 or 35 or 37 or 38 or 50 or 51 or 53 or 54;
    private static bool TargetIsPayload(int basic) => basic is 2 or 18 or 34 or 37 or 38 or 50 or 51;
    private static bool IsFalse(string condition) => condition.Trim() == "0";
    private static bool IsUnconditional(string condition) => condition.Trim() is "" or "1";
    private static bool SensitiveProperty(string name) => new[] { "password", "passwd", "token", "secret", "authorization", "cookie", "sessionid" }.Any(word => name.Contains(word, StringComparison.OrdinalIgnoreCase));
    internal static string RedactedTarget(MsiCustomAction action) => (action.Type.GetValueOrDefault() & 0x2000) != 0 || BasicType(action.Type) == 51 && SensitiveProperty(action.Source) ? "[隐藏的敏感 Target]" : ScriptSignals.Redact(action.Target);
    private static string LongName(string name) => name.Contains('|') ? name[(name.IndexOf('|') + 1)..] : name;
    private static bool SafeSegment(string name) => name.Length > 0 && name is not "." and not ".." && name.IndexOfAny(['\\', '/', ':', '[', ']', '\0']) < 0;
    private static Resolution Combine(Resolution first, Resolution second) => new(first.Text + " " + second.Text, first.Complete && second.Complete);
    private static string Display(string value, int maximum) { string safe = ScriptSignals.Redact(value).Replace('\r', ' ').Replace('\n', ' '); return safe.Length > maximum ? safe[..maximum] + "…" : safe; }
    private static string SequenceLabel(int? sequence) => sequence switch { null => "NULL（未排入正常顺序）", 0 => "0（不执行）", >= 1 => sequence.Value.ToString(), >= -4 => sequence.Value + "（结束状态处理，不连接正常顺序）", _ => sequence.Value + "（非正常执行顺序）" };
    internal static string DescribeType(int? type)
    {
        int basic = BasicType(type);
        string meaning = basic switch
        {
            1 => "Binary DLL",
            2 => "Binary EXE",
            5 => "Binary JScript",
            6 => "Binary VBScript",
            17 => "File DLL",
            18 => "File EXE",
            21 => "File JScript",
            22 => "File VBScript",
            19 => "错误消息",
            34 => "Directory EXE",
            35 => "设置 Directory",
            37 => "内联 JScript",
            38 => "内联 VBScript",
            50 => "Property EXE",
            51 => "设置 Property",
            53 => "Property JScript",
            54 => "Property VBScript",
            _ => "未支持类型"
        };
        if (type is null) return "Type=NULL（未解析）";
        List<string> flags = [];
        if ((type & 0x40) != 0) flags.Add("忽略返回码");
        if ((type & 0x80) != 0) flags.Add("异步");
        if ((type & 0x400) != 0)
        {
            flags.Add((type & 0x300) switch { 0x100 => "回滚脚本", 0x200 => "提交脚本", 0 => "延迟脚本", _ => "未知脚本调度组合" });
        }
        else if ((type & 0x300) != 0) flags.Add((type & 0x300) switch { 0x100 => "首个序列", 0x200 => "每进程一次", _ => "客户端重复" });
        if ((type & 0x800) != 0) flags.Add("不模拟用户");
        if ((type & 0x1000) != 0) flags.Add("64 位脚本");
        if ((type & 0x2000) != 0) flags.Add("隐藏 Target 日志");
        if ((type & 0x4000) != 0) flags.Add("终端服务上下文");
        if ((type & 0x8000) != 0) flags.Add("补丁卸载");
        return $"Type={type}，基本类型={basic} {meaning}" + (flags.Count == 0 ? "" : "，" + string.Join("/", flags));
    }
    private sealed record Resolution(string Text, bool Complete) { public override string ToString() => Text; }
}
