using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace SteamSentinel.Core.Inspection;

/// <summary>Reads a fixed table projection from an already open, read-only MSI database.</summary>
internal static class MsiDatabaseReader
{
    internal const int MaximumTableRows = 4096;
    internal const int MaximumTotalRows = 16384;
    internal const int MaximumTextCharacters = 2 * 1024 * 1024;
    internal const int MaximumFieldCharacters = 8192;

    internal static MsiInspection Read(uint database, CancellationToken token, Action? checkpoint = null)
    {
        MsiInspection result = new();
        HashSet<string> names = new(StringComparer.Ordinal);
        int totalRows = 0, textCharacters = 0;
        bool textBudgetExhausted = false;
        MsiTableRead discovery = ReadTable("_Tables", "SELECT `Name` FROM `_Tables`", 1, fields => names.Add(fields[0]));
        result.Tables.Add(discovery);
        result.Recognized = names.Contains("Property") || names.Contains("File") || names.Contains("CustomAction");
        if (!result.Recognized) return result;

        Read("Property", "`Property`,`Value`", 2, f => result.Properties.Add(new(f[0], f[1])));
        Read("Directory", "`Directory`,`Directory_Parent`,`DefaultDir`", 3, f => result.Directories.Add(new(f[0], f[1], f[2])));
        Read("Component", "`Component`,`Directory_`,`Condition`,`KeyPath`", 4, f => result.Components.Add(new(f[0], f[1], f[2], f[3])));
        Read("File", "`File`,`Component_`,`FileName`,`FileSize`,`Sequence`", 5, f => result.Files.Add(new(f[0], f[1], f[2], Long(f[3]), Number(f[4]))));
        Read("Media", "`DiskId`,`LastSequence`,`Cabinet`", 3, f => result.Media.Add(new(Number(f[0]), Number(f[1]), f[2])));
        Read("CustomAction", "`Action`,`Type`,`Source`,`Target`", 4, f => result.Actions.Add(new(f[0], Number(f[1]), f[2], f[3])));
        foreach (string table in new[] { "InstallExecuteSequence", "InstallUISequence" })
            Read(table, "`Action`,`Condition`,`Sequence`", 3, f => result.Sequences.Add(new(table, f[0], f[1], Number(f[2]))));
        Read("Registry", "`Registry`,`Root`,`Key`,`Name`,`Value`,`Component_`", 6, f => result.Registry.Add(new(f[0], Number(f[1]), f[2], f[3], f[4], f[5])));
        Read("Shortcut", "`Shortcut`,`Directory_`,`Name`,`Component_`,`Target`,`Arguments`,`WkDir`", 7, f => result.Shortcuts.Add(new(f[0], f[1], f[2], f[3], f[4], f[5], f[6])));
        // Deliberately do not project ServiceInstall.Password or the MSI property bag into reports.
        Read("ServiceInstall", "`ServiceInstall`,`Name`,`ServiceType`,`StartType`,`Arguments`,`Component_`", 6, f => result.Services.Add(new(f[0], f[1], Number(f[2]), Number(f[3]), f[4], f[5])));
        Read("ServiceControl", "`ServiceControl`,`Name`,`Event`,`Arguments`,`Component_`", 5, f => result.ServiceControls.Add(new(f[0], f[1], Number(f[2]), f[3], f[4])));
        Read("Binary", "`Name`", 1, f => result.BinaryNames.Add(f[0]));
        return result;

        void Read(string table, string projection, int columns, Action<string[]> add)
        {
            if (!names.Contains(table))
            {
                result.Tables.Add(new(table, discovery.State == MsiReadState.Complete ? MsiReadState.Absent : MsiReadState.NotChecked, 0,
                    discovery.State == MsiReadState.Complete ? "表不存在" : "表目录未完整读取，不能确认不存在"));
                return;
            }
            if (totalRows >= MaximumTotalRows || textBudgetExhausted || textCharacters >= MaximumTextCharacters)
            { result.Tables.Add(new(table, MsiReadState.NotChecked, 0, "安装表共享读取预算已耗尽")); return; }
            result.Tables.Add(ReadTable(table, $"SELECT {projection} FROM `{table}`", columns, add));
        }

        MsiTableRead ReadTable(string table, string sql, int columns, Action<string[]> add)
        {
            token.ThrowIfCancellationRequested();
            checkpoint?.Invoke();
            uint code = MsiDatabaseOpenView(database, sql, out uint view);
            if (code != 0) return new(table, MsiReadState.Failed, 0, $"固定 SELECT 打开失败，错误 {code}");
            int rows = 0;
            try
            {
                code = MsiViewExecute(view, 0);
                if (code != 0) return new(table, MsiReadState.Failed, 0, $"固定 SELECT 读取失败，错误 {code}");
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    checkpoint?.Invoke();
                    code = MsiViewFetch(view, out uint record);
                    if (code == 259) return new(table, MsiReadState.Complete, rows);
                    if (code != 0) return new(table, MsiReadState.Failed, rows, $"表行读取失败，错误 {code}");
                    try
                    {
                        if (rows >= MaximumTableRows || totalRows >= MaximumTotalRows)
                            return new(table, MsiReadState.LimitReached, rows, "表行数或共享行数达到上限");
                        string[] fields = new string[columns];
                        for (int i = 0; i < columns; i++)
                        {
                            fields[i] = ReadField(record, (uint)i + 1);
                            if (textCharacters + fields[i].Length > MaximumTextCharacters)
                            {
                                textBudgetExhausted = true;
                                return new(table, MsiReadState.LimitReached, rows, "安装表共享文本预算达到上限");
                            }
                            textCharacters += fields[i].Length;
                        }
                        add(fields); rows++; totalRows++;
                    }
                    catch (InvalidDataException ex) { return new(table, MsiReadState.LimitReached, rows, ex.Message); }
                    catch (IOException ex) { return new(table, MsiReadState.Failed, rows, ex.Message); }
                    finally { MsiCloseHandle(record); }
                }
            }
            finally { MsiCloseHandle(view); }
        }
    }

    private static int? Number(string value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : null;
    private static long? Long(string value) => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long result) ? result : null;
    private static string ReadField(uint record, uint field)
    {
        uint length = MaximumFieldCharacters + 1; // Input capacity includes the NUL terminator.
        StringBuilder buffer = new(MaximumFieldCharacters + 1);
        uint code = MsiRecordGetString(record, field, buffer, ref length);
        if (code == 234) throw new InvalidDataException("安装数据库字段超过读取上限");
        if (code != 0) throw new IOException($"安装数据库字段读取失败，错误 {code}");
        if (length > MaximumFieldCharacters) throw new InvalidDataException("安装数据库字段超过读取上限");
        return buffer.ToString();
    }

    [DllImport("msi.dll", EntryPoint = "MsiDatabaseOpenViewW", CharSet = CharSet.Unicode)] private static extern uint MsiDatabaseOpenView(uint database, string sql, out uint view);
    [DllImport("msi.dll")] private static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll")] private static extern uint MsiViewFetch(uint view, out uint record);
    [DllImport("msi.dll", EntryPoint = "MsiRecordGetStringW", CharSet = CharSet.Unicode)] private static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll")] private static extern uint MsiCloseHandle(uint handle);
}
