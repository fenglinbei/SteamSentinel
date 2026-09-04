using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Inspection;

public sealed record StructuredMember(string Name, string Path, long Size);
public sealed class StructuredInspection
{
    public bool Recognized { get; set; }
    public List<string> Notes { get; } = [];
    public List<string> Metadata { get; } = [];
    public List<StructuredMember> Members { get; } = [];
    public long ExpandedBytes { get; set; }
}

/// <summary>Windows installation database and cabinet READ APIs only. Never installs, repairs or invokes custom actions.</summary>
public static class StructuredContainerInspector
{
    private const int MaxRows = 4096;
    public static StructuredInspection ReadMsi(string path, TemporaryDirectory temp, long perEntry,
        long remainingBytes, int maximumEntries, CancellationToken token)
    {
        StructuredInspection result = new();
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.Notes.Add("安装包路径不是安全的本地路径"); return result; }
        uint error = MsiOpenDatabase(path, IntPtr.Zero, out uint database); // MSIDBOPEN_READONLY
        if (error != 0) { result.Notes.Add($"无法以只读方式打开 MSI/复合文档，错误 {error}"); return result; }
        try
        {
            HashSet<string> tables = [];
            Query(database, "SELECT `Name` FROM `_Tables`", record => tables.Add(ReadString(record, 1)), result, token);
            result.Recognized = tables.Contains("Property") || tables.Contains("File") || tables.Contains("CustomAction");
            if (!result.Recognized) { result.Notes.Add("不是本工具支持的 MSI 安装数据库"); return result; }
            foreach ((string table, string query, int columns) in new[]
            {
                ("CustomAction", "SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`", 4),
                ("InstallExecuteSequence", "SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`", 3),
                ("InstallUISequence", "SELECT `Action`,`Condition`,`Sequence` FROM `InstallUISequence`", 3),
                ("File", "SELECT `File`,`Component_`,`FileName`,`FileSize` FROM `File`", 4),
                ("Media", "SELECT `DiskId`,`LastSequence`,`Cabinet` FROM `Media`", 3)
            })
            {
                if (!tables.Contains(table)) continue;
                Query(database, query, record =>
                {
                    string[] fields = Enumerable.Range(1, columns).Select(index => ReadString(record, (uint)index)).ToArray();
                    result.Metadata.Add(table + ": " + string.Join(" | ", fields));
                    if (table == "Media" && fields[2].Length > 0 && !fields[2].StartsWith('#'))
                        result.Notes.Add("安装包引用外部 CAB，未访问或下载：" + fields[2]);
                }, result, token);
            }
            if (tables.Contains("Binary"))
                Query(database, "SELECT `Name`,`Data` FROM `Binary`", record => Extract(record, false), result, token);
            Query(database, "SELECT `Name`,`Data` FROM `_Streams`", record => Extract(record, true), result, token);

            void Extract(uint record, bool cabinetsOnly)
            {
                token.ThrowIfCancellationRequested();
                string name = ReadString(record, 1);
                byte[] buffer = new byte[64 * 1024];
                uint count = (uint)buffer.Length;
                uint code = MsiRecordReadStream(record, 2, buffer, ref count);
                if (code != 0) { result.Notes.Add($"安装包成员无法读取：{name}，错误 {code}"); return; }
                bool cabinet = count >= 4 && buffer.AsSpan(0, 4).SequenceEqual("MSCF"u8);
                if (cabinetsOnly && !cabinet) return;
                if (result.Members.Count >= Math.Min(maximumEntries, 1024)) { result.Notes.Add("安装包成员数量达到上限"); return; }
                string output = temp.CreateFilePath();
                long total = 0;
                try
                {
                    using FileStream stream = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    while (count > 0)
                    {
                        token.ThrowIfCancellationRequested();
                        if (total + count > perEntry || result.ExpandedBytes + count > remainingBytes)
                            throw new InvalidDataException("安装包成员展开达到大小上限");
                        stream.Write(buffer, 0, (int)count);
                        total += count;
                        result.ExpandedBytes += count;
                        count = (uint)buffer.Length;
                        code = MsiRecordReadStream(record, 2, buffer, ref count);
                        if (code != 0) throw new IOException($"安装包成员读取失败，错误 {code}");
                    }
                    result.Members.Add(new((cabinetsOnly ? "cabinet/" : "binary/") + name + (cabinet ? ".cab" : ""), output, total));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { result.Notes.Add($"{name}：{ex.Message}"); }
                finally { Array.Clear(buffer); }
            }
        }
        finally { MsiCloseHandle(database); }
        return result;
    }

    private static void Query(uint database, string sql, Action<uint> row, StructuredInspection result, CancellationToken token)
    {
        uint code = MsiDatabaseOpenView(database, sql, out uint view);
        if (code != 0) { result.Notes.Add($"安装数据库表读取失败，错误 {code}"); return; }
        try
        {
            code = MsiViewExecute(view, 0); // Executes a fixed SELECT, not an installation action.
            if (code != 0) { result.Notes.Add($"安装数据库查询失败，错误 {code}"); return; }
            int rows = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                code = MsiViewFetch(view, out uint record);
                if (code == 259) break;
                if (code != 0) { result.Notes.Add($"安装数据库行读取失败，错误 {code}"); break; }
                try
                {
                    if (++rows > MaxRows) { result.Notes.Add("安装数据库表行数达到上限"); break; }
                    row(record);
                }
                finally { MsiCloseHandle(record); }
            }
        }
        finally { MsiCloseHandle(view); }
    }

    private static string ReadString(uint record, uint field)
    {
        uint length = 8192;
        StringBuilder buffer = new(8193);
        uint code = MsiRecordGetString(record, field, buffer, ref length);
        if (code == 234) throw new InvalidDataException("安装数据库字段超过读取上限");
        if (code != 0) throw new IOException($"安装数据库字段读取失败，错误 {code}");
        return buffer.ToString();
    }

    public static StructuredInspection ReadCabinet(string path, TemporaryDirectory temp, long perEntry,
        long remainingBytes, int maximumEntries, CancellationToken token)
    {
        StructuredInspection result = new() { Recognized = true };
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.Notes.Add("CAB 路径不是安全的本地路径"); return result; }
        Exception? failure = null;
        int visited = 0;
        CabinetCallback callback = (_, message, first, _) =>
        {
            try
            {
                token.ThrowIfCancellationRequested();
                if (message == 0x11) // SPFILENOTIFY_FILEINCABINET
                {
                    if (++visited > Math.Min(maximumEntries, 1024)) { result.Notes.Add("CAB 成员数量达到上限"); return 0; }
                    CabinetFile info = Marshal.PtrToStructure<CabinetFile>(first);
                    if (result.Members.Count >= Math.Min(maximumEntries, 1024) || info.FileSize > perEntry ||
                        result.ExpandedBytes + info.FileSize > remainingBytes)
                    { result.Notes.Add("CAB 展开达到数量或大小上限"); return 2; } // FILEOP_SKIP
                    string name = Marshal.PtrToStringUni(info.NameInCabinet) ?? "<未命名>";
                    string output = temp.CreateFilePath();
                    if (output.Length >= 260) { result.Notes.Add("CAB 临时路径超过系统接口限制"); return 2; }
                    info.FullTargetName = output; // Never use the attacker-controlled member name as a path.
                    Marshal.StructureToPtr(info, first, false);
                    result.Members.Add(new(name, output, info.FileSize));
                    result.ExpandedBytes += info.FileSize;
                    return 1; // FILEOP_DOIT
                }
                if (message == 0x12) { result.Notes.Add("CAB 引用其他分卷，未访问外部路径"); return 13; }
                if (message == 0x13)
                {
                    FilePaths info = Marshal.PtrToStructure<FilePaths>(first);
                    return info.Win32Error;
                }
                return 0;
            }
            catch (Exception ex) { failure = ex; return message == 0x11 ? 0u : 13u; }
        };
        bool success = SetupIterateCabinet(path, 0, callback, IntPtr.Zero);
        GC.KeepAlive(callback);
        if (failure is OperationCanceledException) throw failure;
        if (failure is not null) result.Notes.Add(failure.Message);
        if (!success) result.Notes.Add("CAB 未完整展开：" + new Win32Exception(Marshal.GetLastWin32Error()).Message);
        foreach (StructuredMember member in result.Members.ToArray())
            if (!File.Exists(member.Path) || !ContentDiscovery.IsLocalSafePath(member.Path) || new FileInfo(member.Path).Length != member.Size)
            { result.Members.Remove(member); result.Notes.Add("CAB 成员未能完整提取：" + member.Name); }
        return result;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CabinetFile
    {
        public IntPtr NameInCabinet;
        public uint FileSize, Win32Error;
        public ushort DosDate, DosTime, DosAttribs;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FullTargetName;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FilePaths { public IntPtr Target, Source; public uint Win32Error, Flags; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint CabinetCallback(IntPtr context, uint message, IntPtr first, IntPtr second);
    [DllImport("setupapi.dll", EntryPoint = "SetupIterateCabinetW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetupIterateCabinet(string path, uint reserved, CabinetCallback callback, IntPtr context);
    [DllImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", CharSet = CharSet.Unicode)] private static extern uint MsiOpenDatabase(string path, IntPtr mode, out uint database);
    [DllImport("msi.dll", EntryPoint = "MsiDatabaseOpenViewW", CharSet = CharSet.Unicode)] private static extern uint MsiDatabaseOpenView(uint database, string sql, out uint view);
    [DllImport("msi.dll")] private static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll")] private static extern uint MsiViewFetch(uint view, out uint record);
    [DllImport("msi.dll", EntryPoint = "MsiRecordGetStringW", CharSet = CharSet.Unicode)] private static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll")] private static extern uint MsiRecordReadStream(uint record, uint field, [Out] byte[] buffer, ref uint count);
    [DllImport("msi.dll")] private static extern uint MsiCloseHandle(uint handle);
}
