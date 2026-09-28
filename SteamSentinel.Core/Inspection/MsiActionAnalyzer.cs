using SteamSentinel.Core.Reporting;
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
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.01", (table.Table), (table.State), (table.Rows)) + (table.Detail.Length == 0 ? "" : "；" + table.Detail));
            if (table.State is MsiReadState.Failed or MsiReadState.LimitReached or MsiReadState.NotChecked)
                Gap($"{table.Table}: {table.State}，{table.Detail}");
        }
        if (data.Actions.Count > MaximumActions) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.02", (MaximumActions), (data.Actions.Count - MaximumActions)));
        foreach (MsiCustomAction action in data.Actions.Take(MaximumActions))
        {
            token.ThrowIfCancellationRequested();
            int basic = BasicType(action.Type);
            MessageText type = DescribeTypeText(action.Type);
            MsiSequence[] schedules = sequences[action.Action].ToArray();
            MessageText placement = schedules.Length == 0 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.03") : MessageText.Join("；", schedules.Take(8).Select(s =>
                MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.04", (s.Table), (SequenceLabel(s.Sequence)), (DisplayTextValue(s.Condition.Length == 0 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.05") : s.Condition, 180)))));
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.06", (action.Action), (type), (placement)));
            if (schedules.Length > 8) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.07", (action.Action)));
            if (!Supported(basic)) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.08", (action.Action), (action.Type?.ToString() ?? "NULL")));

            // Preserve the established rule on one literal action payload, including Type 51
            // property text. Names, unrelated actions and sequence labels never become code.
            if (TargetIsPayload(basic))
            {
                foreach (MessageText signal in ScriptSignals.AnalyzeMessages(action.Target))
                    AddUnique(result.ContentSignals, Display(action.Action, 80) + ": " + signal + (basic == 51 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.09") : MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.10")));
            }
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.11", (action.Action), (SourceReference(action, null).TextValue), (DisplayTextValue(RedactedTargetText(action), 640))));
            if (basic == 51 && action.Source.Length == 0) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.12", (action.Action)));

            foreach (MsiSequence schedule in schedules.Take(8))
            {
                if (schedule.Sequence is null or <= 0 || IsFalse(schedule.Condition)) continue;
                if (!Supported(basic) || basic is 19 or 35 or 51) continue;
                if ((action.Type.GetValueOrDefault() & 0x400) != 0)
                { Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.13", (action.Action))); continue; }
                if (!TableComplete("CustomAction") || !TableComplete(schedule.Table))
                { Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.14", (action.Action))); continue; }
                if (!actions.ContainsKey(action.Action)) { Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.15", (action.Action))); continue; }
                Resolution payload = Payload(action, schedule);
                Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.16", (action.Action), (schedule.Table), (schedule.Sequence), (((action.Type.GetValueOrDefault() & 0x2000) != 0 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.17") : payload.TextValue)), (payload.Complete), (Timing(schedule))));
                if (payload.Complete)
                    foreach (MessageText signal in ScriptSignals.AnalyzeMessages(payload.Text))
                        AddUnique(result.LinkedSignals, MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.18", (Display(action.Action, 80)), (schedule.Table), (schedule.Sequence), (signal)));
            }
        }

        foreach (MsiFile file in data.Files.Take(96))
        {
            Resolution path = FilePath(file.Id, new HashSet<string>(StringComparer.Ordinal), 0);
            MsiMedia? media = file.Sequence is > 0 ? data.Media.Where(m => m.LastSequence >= file.Sequence).OrderBy(m => m.LastSequence).FirstOrDefault() : null;
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.19", (file.Id), (file.Component), (path.TextValue), (file.Sequence?.ToString() ?? "NULL"), ((MessageText?)media?.DiskId?.ToString() ?? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.20")), (media?.Cabinet ?? "")));
        }
        if (data.Files.Count > 96) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.21", (data.Files.Count - 96)));
        foreach (MsiRegistry row in data.Registry.Take(16))
        {
            MessageText root = row.Root switch { 0 => "HKCR", 1 => "HKCU", 2 => "HKLM", 3 => "HKU", -1 => MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.22"), _ => MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.23") };
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.24", (row.Id), (root), (row.Key), (row.Name), (Display(row.Value, 256)), (ComponentReference(row.Component))));
        }
        foreach (MsiShortcut row in data.Shortcuts.Take(16))
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.25", (row.Id), (DirectoryPath(row.Directory, new(StringComparer.Ordinal), 0).TextValue), (LongName(row.Name)), (row.Target), (Display(row.Arguments, 256)), (row.WorkingDirectory), (ComponentReference(row.Component))));
        foreach (MsiServiceInstall row in data.Services.Take(16))
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.26", (row.Id), (row.Name), (row.ServiceType), (row.StartType), (Display(row.Arguments, 256)), (ComponentReference(row.Component))));
        foreach (MsiServiceControl row in data.ServiceControls.Take(16))
            Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.27", (row.Id), (row.Name), (row.Event), (Display(row.Arguments, 256)), (ComponentReference(row.Component))));
        foreach ((string table, int count) in new[] { ("Registry", data.Registry.Count), ("Shortcut", data.Shortcuts.Count), ("ServiceInstall", data.Services.Count), ("ServiceControl", data.ServiceControls.Count) })
            if (count > 16) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.28", (table), (count - 16)));
        foreach (MsiMedia media in data.Media.Where(m => m.Cabinet.Length > 0 && !m.Cabinet.StartsWith('#')).Take(16))
            Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.29") + Display(media.Cabinet, 180));
        Evidence(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.30"));
        return result;

        MessageText ComponentReference(string id)
        {
            if (!components.TryGetValue(id, out MsiComponent? component)) { Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.31") + Display(id, 100)); return "Component=" + id + MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.32"); }
            MessageText key = files.ContainsKey(component.KeyPath) ? FilePath(component.KeyPath, new(StringComparer.Ordinal), 0).TextValue : component.KeyPath + MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.33");
            return $"Component={id}，Directory={DirectoryPath(component.Directory, new(StringComparer.Ordinal), 0).TextValue}，KeyPath={key}，Condition={Display(component.Condition, 100)}";
        }
        Resolution SourceReference(MsiCustomAction action, MsiSequence? schedule)
        {
            int basic = BasicType(action.Type);
            if (basic is 1 or 2 or 5 or 6)
            {
                bool found = data.BinaryNames.Contains(action.Source);
                if (!found) Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.34", (action.Action), (Display(action.Source, 100))));
                return new("Binary:" + action.Source + (found ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.35") : MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.36")), found);
            }
            if (basic is 17 or 18 or 21 or 22) return FilePath(action.Source, new(StringComparer.Ordinal), 0);
            if (basic is 34 or 35)
            {
                Resolution directory = DirectoryPath(action.Source, new(StringComparer.Ordinal), 0);
                return new((basic == 34 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.37") : MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.38")) + directory.TextValue, directory.Complete);
            }
            if (basic is 50 or 53 or 54)
                return schedule is null ? new("Property:" + action.Source + MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.39"), false) : Property(action.Source, schedule, new(StringComparer.Ordinal), 0);
            if (basic == 51) return new(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.40") + action.Source, true);
            return new(basic is 37 or 38 ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.41") : (MessageText)("Source:" + action.Source), basic is 37 or 38 or 19);
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
            if (basic == 34) return new(target.TextValue, source.Complete && target.Complete);
            // Binary/File script and DLL bodies live in separately scanned members.
            // The Target entrypoint/argument text is not their executable body.
            if (basic is 1 or 5 or 6 or 17 or 21 or 22) return new(source.TextValue + "; Target=" + target.TextValue, false);
            if (basic == 2) return new(target.TextValue, source.Complete && target.Complete);
            return new(target.TextValue, false);
        }
        Resolution Property(string name, MsiSequence schedule, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.42"), false);
            if (SensitiveProperty(name)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.43") + name, MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.44"));
            if (depth >= MaximumReferenceDepth || !visiting.Add("P:" + name)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.45") + name, "[" + name + "]");
            try
            {
                if (!TableComplete("Property", allowAbsent: true)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.46") + name, "[" + name + "]");
                var setters = assignments[name].Where(a => a.Action != schedule.Action).SelectMany(a => sequences[a.Action].Where(s => s.Table == schedule.Table && s.Sequence is > 0 && s.Sequence <= schedule.Sequence)
                    .Select(s => (Action: a, Schedule: s))).Where(s => !IsFalse(s.Schedule.Condition)).ToArray();
                if (setters.Length > 0)
                {
                    int? latest = setters.Max(s => s.Schedule.Sequence);
                    var candidates = setters.Where(s => s.Schedule.Sequence == latest).ToArray();
                    if (latest == schedule.Sequence || candidates.Length != 1 || !IsUnconditional(candidates[0].Schedule.Condition))
                        return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.47") + name, "[" + name + "]");
                    MsiCustomAction setter = candidates[0].Action;
                    if ((setter.Type.GetValueOrDefault() & 0x700) != 0)
                        return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.48") + name, "[" + name + "]");
                    // Type51 evaluates at its own earlier position, so repeated assignments can
                    // refer to an earlier value of the same property without a false self-cycle.
                    HashSet<string> earlier = new(visiting, StringComparer.Ordinal);
                    earlier.Remove("P:" + name);
                    return Format(setter.Target, candidates[0].Schedule, earlier, depth + 1);
                }
                if (!properties.TryGetValue(name, out MsiProperty? property)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.49") + name, "[" + name + "]");
                // Values in Property are literal. MSI does not recursively expand their brackets.
                return new(property.Value, true);
            }
            finally { visiting.Remove("P:" + name); }
        }
        Resolution Format(string text, MsiSequence schedule, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.50"), false);
            if (depth >= MaximumReferenceDepth) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.51"), Display(text, 256));
            StringBuilder output = new(); bool complete = true;
            for (int i = 0; i < text.Length; i++)
            {
                if ((i & 127) == 0) token.ThrowIfCancellationRequested();
                if (text[i] != '[') output.Append(text[i]);
                else
                {
                    int end = text.IndexOf(']', i + 1);
                    if (end < 0) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.52"), Display(text, 256));
                    string reference = text[(i + 1)..end]; Resolution value;
                    if (reference.StartsWith('\\') && reference.Length == 2) value = new(reference[1].ToString(), true);
                    else if (reference == "~") value = new("<NUL>", false);
                    else if (reference.StartsWith('#') && Identifier.IsMatch(reference[1..])) value = FilePath(reference[1..], new(StringComparer.Ordinal), 0);
                    else if (reference.StartsWith('$') && Identifier.IsMatch(reference[1..]) && components.TryGetValue(reference[1..], out MsiComponent? component)) value = DirectoryPath(component.Directory, new(StringComparer.Ordinal), 0);
                    else if (Identifier.IsMatch(reference)) value = Property(reference, schedule, visiting, depth + 1);
                    else value = Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.53") + Display(reference, 100), "[" + reference + "]");
                    output.Append(value.Text); complete &= value.Complete; i = end;
                }
                if (output.Length > MaximumResolvedCharacters) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.54"), output.ToString(0, 256));
            }
            return new(output.ToString(), complete);
        }
        Resolution FilePath(string id, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[#" + id + "]", false);
            if (!files.TryGetValue(id, out MsiFile? file)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.55") + id, "[#" + id + "]");
            if (!components.TryGetValue(file.Component, out MsiComponent? component)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.56") + file.Component, "[#" + id + "]");
            Resolution parent = DirectoryPath(component.Directory, visiting, depth + 1);
            string name = LongName(file.Name);
            if (!SafeSegment(name)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.57") + id, "[#" + id + "]");
            return new(parent.TextValue + "\\" + name, parent.Complete);
        }
        Resolution DirectoryPath(string id, HashSet<string> visiting, int depth)
        {
            if (!SpendResolution()) return new("[" + id + "]", false);
            if (depth >= MaximumReferenceDepth || !visiting.Add(id)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.58") + id, "[" + id + "]");
            try
            {
                if (!directories.TryGetValue(id, out MsiDirectory? directory)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.59") + id, "[" + id + "]");
                if (StandardDirectories.Contains(id)) return new("[" + id + "]", true);
                string segment = LongName(directory.DefaultDir.Split(':')[0]);
                if (directory.Parent.Length == 0) return new("[" + id + "]", true);
                Resolution parent = DirectoryPath(directory.Parent, visiting, depth + 1);
                if (segment == ".") return parent;
                if (!SafeSegment(segment)) return Unknown(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.60") + id, "[" + id + "]");
                return new(parent.TextValue + "\\" + segment, parent.Complete);
            }
            finally { visiting.Remove(id); }
        }
        MessageText Timing(MsiSequence schedule)
        {
            MsiSequence? finalize = sequences["InstallFinalize"].FirstOrDefault(s => s.Table == schedule.Table && s.Sequence > 0);
            return finalize is not null && schedule.Sequence > finalize.Sequence ? MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.61") : MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.62");
        }
        bool TableComplete(string table, bool allowAbsent = false) => data.Tables.FirstOrDefault(t => t.Table == table)?.State is MsiReadState.Complete ||
            (allowAbsent && data.Tables.FirstOrDefault(t => t.Table == table)?.State is MsiReadState.Absent);
        bool SpendResolution()
        {
            token.ThrowIfCancellationRequested();
            if (++resolutionSteps <= 32768) return true;
            Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.63"));
            return false;
        }
        Resolution Unknown(MessageText gap, MessageText symbolic) { Gap(gap); return new(symbolic, false); }
        void Evidence(MessageText value)
        {
            MessageText safe = DisplayTextValue(value, 1024);
            if (result.Evidence.Count >= MaximumEvidenceLines || evidenceCharacters + safe.OriginalText.Length > MaximumEvidenceCharacters)
            { if (!evidenceTruncated) { evidenceTruncated = true; Gap(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.64")); } return; }
            result.Evidence.AddText(safe); evidenceCharacters += safe.OriginalText.Length;
        }
        void Gap(MessageText value)
        {
            MessageText safe = DisplayTextValue(value, 256);
            if (result.CoverageGaps.Contains(safe.OriginalText, StringComparer.Ordinal)) return;
            if (result.CoverageGaps.Count < 63) result.CoverageGaps.AddText(safe);
            else if (result.CoverageGaps.Count == 63) result.CoverageGaps.AddText(MessageText.Create("Backend.Core.MsiActionAnalyzer.Analyze.65"));
        }
    }

    private static Dictionary<string, T> Unique<T>(IEnumerable<T> values, Func<T, string> key) => values.GroupBy(key, StringComparer.Ordinal).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.Single(), StringComparer.Ordinal);
    private static void AddUnique(MessageTextCollection values, MessageText value) { if (values.Count < 32 && !values.Contains(value.OriginalText, StringComparer.Ordinal)) values.AddText(value); }
    private static int BasicType(int? type) => type is >= 0 and <= 65535 ? type.Value & 0x3f : -1;
    private static bool Supported(int basic) => basic is 1 or 2 or 5 or 6 or 17 or 18 or 19 or 21 or 22 or 34 or 35 or 37 or 38 or 50 or 51 or 53 or 54;
    private static bool TargetIsPayload(int basic) => basic is 2 or 18 or 34 or 37 or 38 or 50 or 51;
    private static bool IsFalse(string condition) => condition.Trim() == "0";
    private static bool IsUnconditional(string condition) => condition.Trim() is "" or "1";
    private static bool SensitiveProperty(string name) => new[] { "password", "passwd", "token", "secret", "authorization", "cookie", "sessionid" }.Any(word => name.Contains(word, StringComparison.OrdinalIgnoreCase));
    internal static string RedactedTarget(MsiCustomAction action) => RedactedTargetText(action).OriginalText;
    private static MessageText RedactedTargetText(MsiCustomAction action) => (action.Type.GetValueOrDefault() & 0x2000) != 0 || BasicType(action.Type) == 51 && SensitiveProperty(action.Source) ? MessageText.Create("Backend.Core.MsiActionAnalyzer.RedactedTarget.01") : ScriptSignals.Redact(action.Target);
    private static string LongName(string name) => name.Contains('|') ? name[(name.IndexOf('|') + 1)..] : name;
    private static bool SafeSegment(string name) => name.Length > 0 && name is not "." and not ".." && name.IndexOfAny(['\\', '/', ':', '[', ']', '\0']) < 0;
    private static Resolution Combine(Resolution first, Resolution second) => new(first.TextValue + " " + second.TextValue, first.Complete && second.Complete);
    private static string Display(string value, int maximum) { string safe = ScriptSignals.Redact(value).Replace('\r', ' ').Replace('\n', ' '); return safe.Length > maximum ? safe[..maximum] + "…" : safe; }
    private static MessageText SequenceLabel(int? sequence) => sequence switch { null => MessageText.Create("Backend.Core.MsiActionAnalyzer.SequenceLabel.01"), 0 => MessageText.Create("Backend.Core.MsiActionAnalyzer.SequenceLabel.02"), >= 1 => sequence.Value.ToString(), >= -4 => sequence.Value + MessageText.Create("Backend.Core.MsiActionAnalyzer.SequenceLabel.03"), _ => sequence.Value + MessageText.Create("Backend.Core.MsiActionAnalyzer.SequenceLabel.04") };
    internal static string DescribeType(int? type) => DescribeTypeText(type).OriginalText;
    internal static MessageText DescribeTypeText(int? type)
    {
        int basic = BasicType(type);
        MessageText meaning = basic switch
        {
            1 => "Binary DLL",
            2 => "Binary EXE",
            5 => "Binary JScript",
            6 => "Binary VBScript",
            17 => "File DLL",
            18 => "File EXE",
            21 => "File JScript",
            22 => "File VBScript",
            19 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.01"),
            34 => "Directory EXE",
            35 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.02"),
            37 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.03"),
            38 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.04"),
            50 => "Property EXE",
            51 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.05"),
            53 => "Property JScript",
            54 => "Property VBScript",
            _ => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.06")
        };
        if (type is null) return MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.07");
        List<MessageText> flags = [];
        if ((type & 0x40) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.08"));
        if ((type & 0x80) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.09"));
        if ((type & 0x400) != 0)
        {
            flags.Add((type & 0x300) switch { 0x100 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.10"), 0x200 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.11"), 0 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.12"), _ => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.13") });
        }
        else if ((type & 0x300) != 0) flags.Add((type & 0x300) switch { 0x100 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.14"), 0x200 => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.15"), _ => MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.16") });
        if ((type & 0x800) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.17"));
        if ((type & 0x1000) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.18"));
        if ((type & 0x2000) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.19"));
        if ((type & 0x4000) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.20"));
        if ((type & 0x8000) != 0) flags.Add(MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.21"));
        return MessageText.Create("Backend.Core.MsiActionAnalyzer.DescribeType.22", (type), (basic), (meaning)) + (flags.Count == 0 ? (MessageText)"" : "，" + MessageText.Join("/", flags));
    }
    private sealed record Resolution(string Text, bool Complete)
    {
        public SteamSentinel.Core.Models.DisplayMessage? Message { get; init; }
        public MessageText TextValue => new(Text, Message);
        public Resolution(MessageText text, bool complete) : this(text.OriginalText, complete) { Message = text.Message; }
        public override string ToString() => Text;
    }
    private static MessageText DisplayTextValue(MessageText value, int maximum)
    {
        MessageText safe = value.RedactSecrets();
        string flattened = safe.OriginalText.Replace('\r', ' ').Replace('\n', ' ');
        if (flattened != safe.OriginalText) safe = new(flattened);
        if (safe.OriginalText.Length > maximum) return new(safe.OriginalText[..maximum] + "…");
        return safe;
    }
}
