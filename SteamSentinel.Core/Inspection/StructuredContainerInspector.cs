using System.Text.Json.Serialization;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
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
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? NoteMessages { get => SteamSentinel.Core.Models.DisplayMessageMap.Bound(Notes, field); set => field = value; }
    [JsonIgnore] public IEnumerable<MessageText> NoteTexts => DisplayMessageMap.Read(Notes, NoteMessages);
    public void AddNote(MessageText text) => NoteMessages = DisplayMessageMap.Add(Notes, NoteMessages, text);
    public List<string> AccountingNotes { get; } = [];
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public Dictionary<int, DisplayMessage>? AccountingNoteMessages { get; set; }
    [JsonIgnore] public IEnumerable<MessageText> AccountingNoteTexts => DisplayMessageMap.Read(AccountingNotes, AccountingNoteMessages);
    public void AddAccountingNote(MessageText text) => AccountingNoteMessages = DisplayMessageMap.Add(AccountingNotes, AccountingNoteMessages, text);
    public List<string> Metadata { get; } = [];
    public List<StructuredMember> Members { get; } = [];
    public long ExpandedBytes { get; set; }
    internal MsiInspection? Msi { get; set; }
    internal MsiActionAnalysis? MsiAnalysis { get; set; }

    internal void BindBudget(ContainerResourceBudget? budget)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!ReferenceEquals(_budget, budget) || _temporary.Count != 0 || Members.Count != 0 || Msi is not null)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.BindBudget.01"), sourceText => new ArgumentException(sourceText));
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
        long expansionBase = budget?.AcceptedExpandedBytes ?? 0;
        int entryBase = Math.Max(0, (budget?.Limits.MaximumEntries ?? maximumEntries) - maximumEntries);
        result.BindBudget(budget);
        token.ThrowIfCancellationRequested(); budget?.Check();
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.01")); return result; }
        long inputLength = new FileInfo(path).Length;
        budget?.ChargeMetadata(); budget?.ReserveNativeRead(inputLength);
        if (budget is not null) result.AddAccountingNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.02"));
        uint error = MsiOpenDatabase(path, IntPtr.Zero, out uint database); // MSIDBOPEN_READONLY
        if (error != 0) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.03", (error))); return result; }
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
                    EnsureAdaptiveMemberCapacity(budget, count, result.Members.Count + 1, result.ExpandedBytes + count,
                        ref perEntry, ref remainingBytes, ref maximumEntries, expansionBase, entryBase);
                    if (result.Members.Count >= Math.Min(maximumEntries, budget?.Limits.MaximumEntries ?? 1024))
                    {
                        if (budget is not null) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.04"), sourceText => new ScanResourceLimitException(sourceText));
                        result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.05")); return;
                    }
                    EnsureTemporarySpace(temp.Path, 0, budget);
                    output = temp.CreateFilePath(); result.TrackTemporary(output);
                    using (FileStream stream = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        while (count > 0)
                        {
                            token.ThrowIfCancellationRequested(); budget?.Check();
                            EnsureAdaptiveMemberCapacity(budget, total + count, result.Members.Count + 1, result.ExpandedBytes + total + count,
                                ref perEntry, ref remainingBytes, ref maximumEntries, expansionBase, entryBase);
                            // These are member/legacy-adapter bounds. They leave a local
                            // coverage gap; the shared budget below still aborts the run.
                            if (count > Math.Min(perEntry, budget?.Limits.MaximumEntryBytes ?? perEntry) - total ||
                                count > remainingBytes - result.ExpandedBytes - total)
                                throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.06"), sourceText => new InvalidDataException(sourceText));
                            if (budget is not null && total + count > Math.Max(1, inputLength) * budget.Limits.MaximumCompressionRatio &&
                                !ScanResourceSession.Allow("ContainerLimits.MaximumCompressionRatio", checked((long)Math.Ceiling((total + count) / (double)Math.Max(1, inputLength))), known: false))
                                throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.07"), sourceText => new InvalidDataException(sourceText));
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
                    result.AddNote($"{name}：{ex.Message}");
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
                    if (sizeCode != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.08", (sizeCode)), sourceText => new IOException(sourceText));
                    if (remaining == 0) return 0;
                    uint requested = Math.Min(remaining, (uint)(budget?.ReadAllowance(buffer.Length) ?? buffer.Length));
                    uint count = requested;
                    uint code = MsiRecordReadStream(record, 2, buffer, ref count);
                    if (code != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.09", (code)), sourceText => new IOException(sourceText));
                    if (count > requested) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadMsi.10"), sourceText => new IOException(sourceText));
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
        foreach (MessageText gap in result.MsiAnalysis.CoverageGaps.Texts) result.AddNote(gap);
        if (!result.Recognized)
        { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ApplyMsiMetadata.01")); return; }
        // Bounded compatibility summary; raw installation tables stay internal.
        result.Metadata.AddRange(msi.Actions.Take(16).Select(a => ScriptSignals.Redact($"CustomAction: {a.Action} | {a.Type} | {a.Source} | {MsiActionAnalyzer.RedactedTarget(a)}")));
        result.Metadata.AddRange(result.MsiAnalysis.Evidence.Take(16));
    }

    private static void Query(uint database, string sql, Action<uint> row, StructuredInspection result, CancellationToken token,
        ContainerResourceBudget? budget)
    {
        token.ThrowIfCancellationRequested(); budget?.Check(); budget?.ChargeMetadata();
        uint code = MsiDatabaseOpenView(database, sql, out uint view);
        if (code != 0) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.Query.01", (code))); return; }
        try
        {
            code = MsiViewExecute(view, 0); // Executes a fixed SELECT, not an installation action.
            if (code != 0) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.Query.02", (code))); return; }
            int rows = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested(); budget?.Check();
                budget?.ChargeMetadata();
                code = MsiViewFetch(view, out uint record);
                if (code == 259) break;
                if (code != 0) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.Query.03", (code))); break; }
                try
                {
                    if (++rows > MaxRows) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.Query.04")); break; }
                    try { row(record); }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
                    { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.Query.05") + ex.Message); break; }
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
        if (code == 234) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadString.01"), sourceText => new InvalidDataException(sourceText));
        if (code != 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadString.02", (code)), sourceText => new IOException(sourceText));
        return buffer.ToString();
    }

    public static StructuredInspection ReadCabinet(string path, TemporaryDirectory temp, long perEntry,
        long remainingBytes, int maximumEntries, CancellationToken token, ContainerResourceBudget? budget = null,
        StructuredInspection? providedResult = null)
    {
        StructuredInspection result = providedResult ?? new(budget);
        long expansionBase = budget?.AcceptedExpandedBytes ?? 0;
        int entryBase = Math.Max(0, (budget?.Limits.MaximumEntries ?? maximumEntries) - maximumEntries);
        result.BindBudget(budget);
        result.Recognized = true;
        token.ThrowIfCancellationRequested(); budget?.Check();
        if (!ContentDiscovery.IsLocalSafePath(path)) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.01")); return result; }
        long inputLength = new FileInfo(path).Length;
        budget?.ChargeMetadata(); budget?.ReserveNativeRead(inputLength);
        if (budget is not null) result.AddAccountingNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.02"));
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
                    CabinetFile info = Marshal.PtrToStructure<CabinetFile>(first);
                    EnsureAdaptiveMemberCapacity(budget, info.FileSize, visited + 1, result.ExpandedBytes + info.FileSize,
                        ref perEntry, ref remainingBytes, ref maximumEntries, expansionBase, entryBase);
                    int entryLimit = Math.Min(maximumEntries, budget?.Limits.MaximumEntries ?? 1024);
                    if (++visited > entryLimit)
                    {
                        if (budget is not null) throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.03"), sourceText => new ScanResourceLimitException(sourceText));
                        result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.04")); return 0;
                    }
                    if (result.Members.Count >= entryLimit || info.FileSize > Math.Min(perEntry, budget?.Limits.MaximumEntryBytes ?? perEntry) ||
                        info.FileSize > remainingBytes - result.ExpandedBytes)
                    { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.05")); return 2; } // FILEOP_SKIP
                    if (budget is not null && info.FileSize > Math.Max(1, inputLength) * budget.Limits.MaximumCompressionRatio &&
                        !ScanResourceSession.Allow("ContainerLimits.MaximumCompressionRatio", checked((long)Math.Ceiling(info.FileSize / (double)Math.Max(1, inputLength)))))
                    { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.06")); return 2; }
                    string name = ReadBoundedNativeString(info.NameInCabinet, 8192) ?? MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.07");
                    EnsureTemporarySpace(temp.Path, info.FileSize, budget);
                    string output = temp.CreateFilePath();
                    if (output.Length >= 260) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.08")); return 2; }
                    EnsureTemporarySpace(output, info.FileSize, budget);
                    budget?.ReserveNativeDecoded(info.FileSize);
                    if (budget is not null && info.FileSize > budget.Limits.MaximumExpandedBytes - budget.AcceptedExpandedBytes - pendingExpansion)
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.09"), sourceText => new ScanResourceLimitException(sourceText));
                    pendingExpansion = checked(pendingExpansion + info.FileSize);
                    result.ReserveTemporary(output, info.FileSize);
                    ownedTargets.Add(output);
                    info.FullTargetName = output; // Never use the attacker-controlled member name as a path.
                    Marshal.StructureToPtr(info, first, false);
                    result.Members.Add(new(name, output, info.FileSize));
                    result.ExpandedBytes += info.FileSize;
                    return 1; // FILEOP_DOIT
                }
                if (message == 0x12) { result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.10")); return 13; }
                if (message == 0x13)
                {
                    FilePaths info = Marshal.PtrToStructure<FilePaths>(first);
                    string? completedPath = ReadBoundedNativeString(info.Target, 260);
                    if (completedPath is null || !ownedTargets.Contains(completedPath))
                        throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.11"), sourceText => new IOException(sourceText));
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
            if (!success) result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.12") + new Win32Exception(nativeError).Message);
            foreach (StructuredMember member in result.Members.ToArray())
                if (!completedTargets.Contains(member.Path) || !File.Exists(member.Path) ||
                    !ContentDiscovery.IsLocalSafePath(member.Path) || new FileInfo(member.Path).Length != member.Size)
                {
                    result.Members.Remove(member); result.DiscardTemporary(member.Path);
                    result.AddNote(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadCabinet.13") + member.Name);
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
        throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.ReadBoundedNativeString.01"), sourceText => new InvalidDataException(sourceText));
    }

    private static void EnsureTemporarySpace(string path, long bytes, ContainerResourceBudget? budget)
    {
        if (budget is null) { TemporaryDirectory.EnsureFreeSpace(path, bytes); return; }
        budget.Check();
        string volume = Path.GetPathRoot(Path.GetFullPath(path)) ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.EnsureTemporarySpace.01"), sourceText => new IOException(sourceText));
        long reserve = budget.EffectiveDiskReserve;
        if (new DriveInfo(volume).AvailableFreeSpace - reserve < bytes)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.StructuredContainerInspector.EnsureTemporarySpace.02"), sourceText => new ScanResourceLimitException(sourceText));
    }

    private static void EnsureAdaptiveMemberCapacity(ContainerResourceBudget? budget, long length, int entries, long expanded,
        ref long perEntry, ref long remaining, ref int maximumEntries, long expansionBase, int entryBase)
    {
        if (budget is null || ScanResourceSession.Current is null) return;
        if (length > perEntry && ScanResourceSession.Allow("ContainerLimits.MaximumEntryBytes", length, known: false))
            perEntry = budget.Limits.MaximumEntryBytes;
        if (entries > maximumEntries && ScanResourceSession.Allow("ContainerLimits.MaximumEntries", (long)entryBase + entries, known: false))
            maximumEntries = budget.Limits.MaximumEntries - entryBase;
        if (expanded > remaining && ScanResourceSession.Allow("ContainerLimits.MaximumExpandedBytes", checked(expansionBase + expanded), budget.AcceptedExpandedBytes, known: false))
            remaining = budget.Limits.MaximumExpandedBytes - expansionBase;
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
