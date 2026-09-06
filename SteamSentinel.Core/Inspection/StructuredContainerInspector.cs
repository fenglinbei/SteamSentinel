using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Text;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Inspection;

public sealed record StructuredMember(string Name, string Path, long Size);
public sealed class StructuredInspection : IDisposable
{
    private readonly ContainerResourceBudget? _budget;
    private readonly Dictionary<string, long> _temporary = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;
    public StructuredInspection(ContainerResourceBudget? budget = null) => _budget = budget;
    public bool Recognized { get; set; }
    public List<string> Notes { get; } = [];
    public List<string> AccountingNotes { get; } = [];
    public List<string> Metadata { get; } = [];
    public List<StructuredMember> Members { get; } = [];
    public long ExpandedBytes { get; set; }
    internal MsiInspection? Msi { get; set; }
    internal MsiActionAnalysis? MsiAnalysis { get; set; }

    internal void BindBudget(ContainerResourceBudget? budget)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!ReferenceEquals(_budget, budget) || _temporary.Count != 0 || Members.Count != 0 || Msi is not null)
            throw new ArgumentException("结构化检查结果必须属于同一预算且未被其他容器使用。");
    }

    internal void TrackTemporary(string path) => _temporary.TryAdd(path, 0);
    internal void ReserveTemporary(string path, long bytes)
    {
        TrackTemporary(path);
        if (_budget is null) return;
        _budget.ReserveTemporary(bytes);
        _temporary[path] = checked(_temporary[path] + bytes);
    }
    internal void DiscardTemporary(string path)
    {
        if (!_temporary.ContainsKey(path)) return;
        try { if (!Validation.ContainsReparsePoint(path)) File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        ReconcileTemporary(path, _temporary[path]);
    }
    /// <summary>Call again after the owning TemporaryDirectory is disposed; only confirmed deletion refunds occupancy.</summary>
    public void ReconcileTemporary()
    {
        foreach ((string path, long bytes) in _temporary.ToArray())
            ReconcileTemporary(path, bytes);
    }
    private void ReconcileTemporary(string path, long bytes)
    {
        if (File.Exists(path) || Directory.Exists(path)) return;
        if (bytes != 0) _budget!.ReleaseTemporary(bytes);
        _temporary.Remove(path);
    }
    public void Dispose()
    {
        if (_disposed) return;
        foreach (string path in _temporary.Keys.ToArray()) DiscardTemporary(path);
        _disposed = true;
    }
}

/// <summary>Windows installation database and cabinet READ APIs only. Never installs, repairs or invokes custom actions.</summary>
public static class StructuredContainerInspector
{
    private const int MaxRows = 4096;
    public static StructuredInspection ReadMsi(string path, TemporaryDirectory temp, long perEntry,
        long remainingBytes, int maximumEntries, CancellationToken token, ContainerResourceBudget? budget = null,
        StructuredInspection? providedResult = null)
    {
        StructuredInspection result = providedResult ?? new(budget);
        result.BindBudget(budget);
        token.ThrowIfCancellationRequested(); budget?.Check();
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.Notes.Add("安装包路径不是安全的本地路径"); return result; }
        long inputLength = new FileInfo(path).Length;
        budget?.ChargeMetadata(); budget?.ReserveNativeRead(inputLength);
        if (budget is not null) result.AccountingNotes.Add("MSI 原生元数据读取按输入长度独立预留工作预算；不是实测读取量。成员流按实际返回字节计量。");
        uint error = MsiOpenDatabase(path, IntPtr.Zero, out uint database); // MSIDBOPEN_READONLY
        if (error != 0) { result.Notes.Add($"无法以只读方式打开 MSI/复合文档，错误 {error}"); return result; }
        try
        {
            MsiInspection msi = MsiDatabaseReader.Read(database, token, budget is null ? null : budget.ChargeMetadata);
            budget?.Check();
            ApplyMsiMetadata(result, msi, token);
            if (!result.Recognized) return result;
            if (msi.Tables.Any(t => t.Table == "Binary" && t.State != MsiReadState.Absent && t.State != MsiReadState.NotChecked))
                Query(database, "SELECT `Name`,`Data` FROM `Binary`", record => Extract(record, false), result, token, budget);
            Query(database, "SELECT `Name`,`Data` FROM `_Streams`", record => Extract(record, true), result, token, budget);

            void Extract(uint record, bool cabinetsOnly)
            {
                token.ThrowIfCancellationRequested(); budget?.Check();
                string name = ReadString(record, 1);
                byte[] buffer = new byte[64 * 1024];
                string? output = null;
                long total = 0;
                long expansionCheckpoint = budget?.AcceptedExpandedBytes ?? 0;
                bool complete = false;
                try
                {
                    uint count = ReadChunk();
                    bool cabinet = count >= 4 && buffer.AsSpan(0, 4).SequenceEqual("MSCF"u8);
                    if (cabinetsOnly && !cabinet) return;
                    if (result.Members.Count >= Math.Min(maximumEntries, budget?.Limits.MaximumEntries ?? 1024))
                    {
                        if (budget is not null) throw new ScanResourceLimitException("安装包成员数量达到上限");
                        result.Notes.Add("安装包成员数量达到上限"); return;
                    }
                    EnsureTemporarySpace(temp.Path, 0, budget);
                    output = temp.CreateFilePath(); result.TrackTemporary(output);
                    using (FileStream stream = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        while (count > 0)
                        {
                            token.ThrowIfCancellationRequested(); budget?.Check();
                            // These are member/legacy-adapter bounds. They leave a local
                            // coverage gap; the shared budget below still aborts the run.
                            if (count > Math.Min(perEntry, budget?.Limits.MaximumEntryBytes ?? perEntry) - total ||
                                count > remainingBytes - result.ExpandedBytes - total)
                                throw new InvalidDataException("安装包成员展开达到大小上限");
                            if (budget is not null && total + count > Math.Max(1, inputLength) * budget.Limits.MaximumCompressionRatio)
                                throw new InvalidDataException("MSI 成员实际展开比超过本轮单项上限。");
                            budget?.AcceptExpansion(count);
                            EnsureTemporarySpace(output, count, budget);
                            result.ReserveTemporary(output, count);
                            stream.Write(buffer, 0, (int)count);
                            total += count;
                            count = ReadChunk();
                        }
                    }
                    // A failed or partly written member is absent from both logical
                    // expansion counters. Actual decoding work remains charged.
                    result.Members.Add(new((cabinetsOnly ? "cabinet/" : "binary/") + name + (cabinet ? ".cab" : ""), output, total));
                    result.ExpandedBytes = checked(result.ExpandedBytes + total);
                    complete = true;
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
                {
                    if (output is not null) result.DiscardTemporary(output);
                    result.Notes.Add($"{name}：{ex.Message}");
                }
                finally
                {
                    Array.Clear(buffer);
                    if (!complete && budget is not null) budget.RestoreLogicalExpansion(expansionCheckpoint);
                }

                uint ReadChunk()
                {
                    token.ThrowIfCancellationRequested(); budget?.Check();
                    // Null is the documented, non-consuming remaining-size query.
                    // It can confirm EOF even when the last real read used the budget exactly.
                    uint remaining = 0;
                    uint sizeCode = MsiRecordReadStream(record, 2, null, ref remaining);
                    if (sizeCode != 0) throw new IOException($"MSI 成员长度读取失败，错误 {sizeCode}");
                    if (remaining == 0) return 0;
                    uint requested = Math.Min(remaining, (uint)(budget?.ReadAllowance(buffer.Length) ?? buffer.Length));
                    uint count = requested;
                    uint code = MsiRecordReadStream(record, 2, buffer, ref count);
                    if (code != 0) throw new IOException($"安装包成员读取失败，错误 {code}");
                    if (count > requested) throw new IOException("MSI 原生流返回了超出已请求范围的字节数。");
                    budget?.ChargeDecoded(count);
                    return count;
                }
            }
        }
        catch { result.Dispose(); throw; }
        finally { MsiCloseHandle(database); }
        return result;
    }

    internal static void ApplyMsiMetadata(StructuredInspection result, MsiInspection msi, CancellationToken token = default)
    {
        result.Msi = msi;
        result.Recognized = msi.Recognized;
        result.MsiAnalysis = MsiActionAnalyzer.Analyze(msi, token);
        result.Notes.AddRange(result.MsiAnalysis.CoverageGaps);
        if (!result.Recognized)
        { result.Notes.Add("不是本工具支持的 MSI 安装数据库，或表目录未完整读取"); return; }
        // Bounded compatibility summary; raw installation tables stay internal.
        result.Metadata.AddRange(msi.Actions.Take(16).Select(a => ScriptSignals.Redact($"CustomAction: {a.Action} | {a.Type} | {a.Source} | {MsiActionAnalyzer.RedactedTarget(a)}")));
        result.Metadata.AddRange(result.MsiAnalysis.Evidence.Take(16));
    }

    private static void Query(uint database, string sql, Action<uint> row, StructuredInspection result, CancellationToken token,
        ContainerResourceBudget? budget)
    {
        token.ThrowIfCancellationRequested(); budget?.Check(); budget?.ChargeMetadata();
        uint code = MsiDatabaseOpenView(database, sql, out uint view);
        if (code != 0) { result.Notes.Add($"安装数据库表读取失败，错误 {code}"); return; }
        try
        {
            code = MsiViewExecute(view, 0); // Executes a fixed SELECT, not an installation action.
            if (code != 0) { result.Notes.Add($"安装数据库查询失败，错误 {code}"); return; }
            int rows = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested(); budget?.Check();
                budget?.ChargeMetadata();
                code = MsiViewFetch(view, out uint record);
                if (code == 259) break;
                if (code != 0) { result.Notes.Add($"安装数据库行读取失败，错误 {code}"); break; }
                try
                {
                    if (++rows > MaxRows) { result.Notes.Add("安装数据库表行数达到上限"); break; }
                    try { row(record); }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
                    { result.Notes.Add("安装包成员表读取未完成：" + ex.Message); break; }
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
        long remainingBytes, int maximumEntries, CancellationToken token, ContainerResourceBudget? budget = null,
        StructuredInspection? providedResult = null)
    {
        StructuredInspection result = providedResult ?? new(budget);
        result.BindBudget(budget);
        result.Recognized = true;
        token.ThrowIfCancellationRequested(); budget?.Check();
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.Notes.Add("CAB 路径不是安全的本地路径"); return result; }
        long inputLength = new FileInfo(path).Length;
        budget?.ChargeMetadata(); budget?.ReserveNativeRead(inputLength);
        if (budget is not null) result.AccountingNotes.Add("CAB 原生读取按输入长度、原生解码按成员声明长度独立预留工作预算；不是实测读取或解码量。临时占用在写入前预留。");
        Exception? failure = null;
        int visited = 0;
        long pendingExpansion = 0;
        HashSet<string> ownedTargets = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> completedTargets = new(StringComparer.OrdinalIgnoreCase);
        CabinetCallback callback = (_, message, first, _) =>
        {
            if (failure is not null) return message == 0x11 ? 0u : 13u;
            try
            {
                token.ThrowIfCancellationRequested(); budget?.Check();
                if (message == 0x11) // SPFILENOTIFY_FILEINCABINET
                {
                    budget?.ChargeMetadata();
                    int entryLimit = Math.Min(maximumEntries, budget?.Limits.MaximumEntries ?? 1024);
                    if (++visited > entryLimit)
                    {
                        if (budget is not null) throw new ScanResourceLimitException("CAB 成员数量达到上限");
                        result.Notes.Add("CAB 成员数量达到上限"); return 0;
                    }
                    CabinetFile info = Marshal.PtrToStructure<CabinetFile>(first);
                    if (result.Members.Count >= entryLimit || info.FileSize > Math.Min(perEntry, budget?.Limits.MaximumEntryBytes ?? perEntry) ||
                        info.FileSize > remainingBytes - result.ExpandedBytes)
                    { result.Notes.Add("CAB 展开达到数量或大小上限"); return 2; } // FILEOP_SKIP
                    if (budget is not null && info.FileSize > Math.Max(1, inputLength) * budget.Limits.MaximumCompressionRatio)
                    { result.Notes.Add("CAB 成员声明展开比超过本轮单项上限。"); return 2; }
                    string name = ReadBoundedNativeString(info.NameInCabinet, 8192) ?? "<未命名>";
                    EnsureTemporarySpace(temp.Path, info.FileSize, budget);
                    string output = temp.CreateFilePath();
                    if (output.Length >= 260) { result.Notes.Add("CAB 临时路径超过系统接口限制"); return 2; }
                    EnsureTemporarySpace(output, info.FileSize, budget);
                    budget?.ReserveNativeDecoded(info.FileSize);
                    if (budget is not null && info.FileSize > budget.Limits.MaximumExpandedBytes - budget.AcceptedExpandedBytes - pendingExpansion)
                        throw new ScanResourceLimitException("CAB 成员声明展开量超过本轮累计上限。");
                    pendingExpansion = checked(pendingExpansion + info.FileSize);
                    result.ReserveTemporary(output, info.FileSize);
                    ownedTargets.Add(output);
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
                    string? completedPath = ReadBoundedNativeString(info.Target, 260);
                    if (completedPath is null || !ownedTargets.Contains(completedPath))
                        throw new IOException("CAB 原生完成通知未对应本轮自有临时文件。");
                    if (info.Win32Error == 0) completedTargets.Add(completedPath);
                    return info.Win32Error;
                }
                return 0;
            }
            catch (Exception ex) { failure ??= ex; return message == 0x11 ? 0u : 13u; }
        };
        try
        {
            bool success = SetupIterateCabinet(path, 0, callback, IntPtr.Zero);
            int nativeError = Marshal.GetLastPInvokeError();
            if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
            token.ThrowIfCancellationRequested(); budget?.Check();
            if (!success) result.Notes.Add("CAB 未完整展开：" + new Win32Exception(nativeError).Message);
            foreach (StructuredMember member in result.Members.ToArray())
                if (!completedTargets.Contains(member.Path) || !File.Exists(member.Path) ||
                    !ContentDiscovery.IsLocalSafePath(member.Path) || new FileInfo(member.Path).Length != member.Size)
                {
                    result.Members.Remove(member); result.DiscardTemporary(member.Path);
                    result.Notes.Add("CAB 成员未能完整提取：" + member.Name);
                }
                else budget?.AcceptExpansion(member.Size);
            result.ExpandedBytes = result.Members.Sum(member => member.Size);
            return result;
        }
        catch { result.Dispose(); throw; }
        finally { GC.KeepAlive(callback); }
    }

    private static string? ReadBoundedNativeString(IntPtr pointer, int maximumCharacters)
    {
        if (pointer == IntPtr.Zero) return null;
        for (int length = 0; length <= maximumCharacters; length++)
            if (Marshal.ReadInt16(pointer, checked(length * 2)) == 0)
                return Marshal.PtrToStringUni(pointer, length);
        throw new InvalidDataException("CAB 原生元数据字符串超过单项安全读取上限。");
    }

    private static void EnsureTemporarySpace(string path, long bytes, ContainerResourceBudget? budget)
    {
        if (budget is null) { TemporaryDirectory.EnsureFreeSpace(path, bytes); return; }
        budget.Check();
        string volume = Path.GetPathRoot(Path.GetFullPath(path)) ?? throw new IOException("无法确定临时磁盘。");
        long reserve = budget.Limits.ReservedDiskBytes;
        if (new DriveInfo(volume).AvailableFreeSpace - reserve < bytes)
            throw new ScanResourceLimitException("结构化容器展开将侵入本轮保留磁盘空间。");
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
    [DllImport("msi.dll")] private static extern uint MsiRecordReadStream(uint record, uint field, [Out] byte[]? buffer, ref uint count);
    [DllImport("msi.dll")] private static extern uint MsiCloseHandle(uint handle);
}
