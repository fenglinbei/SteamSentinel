using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Diagnostic only. Restart Manager never shuts down or restarts an application.</summary>
public static class FileOccupancy
{
    public const int MaximumProcesses = 16;
    private const int MaximumFiles = 128;
    private const int MaximumNativeProcesses = 256;

    public static FileOccupancyResult Inspect(string path, bool directory = false)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !Validation.IsSafeExactTarget(path) ||
                !Path.IsPathFullyQualified(path) || Validation.ContainsReparsePoint(path))
                return Unknown("占用查询不支持此路径或平台，没有关闭任何进程。");
            List<string> files = [];
            bool partial = false;
            if (directory)
            {
                // RM rejects directory resources. Bound both enumeration and registration, never follow links.
                Stack<string> pending = new(); pending.Push(path);
                int visited = 0;
                while (pending.Count > 0 && !partial)
                {
                    string current = pending.Pop();
                    if (Validation.ContainsReparsePoint(current)) { partial = true; break; }
                    foreach (string child in Directory.EnumerateFileSystemEntries(current))
                    {
                        if (++visited > MaximumFiles) { partial = true; break; }
                        FileAttributes attributes = File.GetAttributes(child);
                        if ((attributes & FileAttributes.ReparsePoint) != 0) { partial = true; continue; }
                        if ((attributes & FileAttributes.Directory) != 0) pending.Push(child);
                        else files.Add(child);
                    }
                }
                // Directory handles themselves are not enumerable by Restart Manager.
                partial = true;
            }
            else files.Add(Path.GetFullPath(path));
            if (files.Count == 0) return Unknown("目录没有可查询文件，目录句柄占用无法由 Restart Manager 确认。", true);
            uint error = RmStartSession(out uint session, 0, new StringBuilder(33));
            if (error != 0) return NativeError("RmStartSession", error);
            try
            {
                error = RmRegisterResources(session, (uint)files.Count, files.ToArray(), 0, IntPtr.Zero, 0, IntPtr.Zero);
                if (error != 0) return NativeError("RmRegisterResources", error);
                uint count = 0;
                error = RmGetList(session, out uint needed, ref count, null, out _);
                for (int attempt = 0; attempt < 3 && error == 234; attempt++)
                {
                    if (needed > MaximumNativeProcesses) return Unknown("占用进程数量超过安全查询上限，结果未知。", true);
                    RmProcessInfo[] records = new RmProcessInfo[Math.Max(1, (int)needed)];
                    count = (uint)records.Length;
                    error = RmGetList(session, out needed, ref count, records, out _);
                    if (error == 0)
                    {
                        List<FileOccupancyProcess> processes = records.Take((int)Math.Min(count, (uint)records.Length))
                            .DistinctBy(record => (record.Process.ProcessId, record.Process.StartTime.dwHighDateTime, record.Process.StartTime.dwLowDateTime))
                            .Take(MaximumProcesses).Select(record => new FileOccupancyProcess
                            {
                                ProcessId = record.Process.ProcessId,
                                ProcessName = RemediationVerification.Limit(record.AppName, 128),
                                StartedAtUtc = StartTime(record.Process.StartTime),
                                ServiceName = RemediationVerification.Limit(record.ServiceName, 128)
                            }).ToList();
                        return new()
                        {
                            Status = processes.Count > 0 ? FileOccupancyStatus.LocksReported : partial ? FileOccupancyStatus.Unknown : FileOccupancyStatus.NoLocksReported,
                            Processes = processes, Truncated = partial || count > MaximumProcesses,
                            Diagnostic = "Restart Manager 只读快照，未关闭进程或句柄。" +
                                (partial ? "目录查询仅覆盖有限文件，不包含目录句柄。" : "未列出进程不等于文件可隔离。")
                        };
                    }
                }
                if (error != 0) return NativeError("RmGetList", error);
                return new() { Status = partial ? FileOccupancyStatus.Unknown : FileOccupancyStatus.NoLocksReported,
                    Truncated = partial, Diagnostic = "Restart Manager 未报告占用，不保证文件可隔离，目录句柄不在覆盖范围。" };
            }
            finally { _ = RmEndSession(session); }
        }
        catch (Exception ex) { return Unknown("占用状态未知：" + RemediationVerification.Limit(ex.Message, 240)); }
    }

    public static string Describe(FileOccupancyResult result) => RemediationVerification.Limit(
        result.Diagnostic + (result.Processes.Count == 0 ? "" : " 占用：" + string.Join("，", result.Processes.Take(MaximumProcesses)
            .Select(process => $"PID {process.ProcessId} {RemediationVerification.Limit(process.ProcessName, 80)}"))), 900);

    private static FileOccupancyResult Unknown(string message, bool partial = false) =>
        new() { Status = FileOccupancyStatus.Unknown, Diagnostic = message, Truncated = partial };
    private static FileOccupancyResult NativeError(string operation, uint code) =>
        Unknown($"{operation} Win32={code}：{RemediationVerification.Limit(new Win32Exception((int)code).Message, 180)}，占用状态未知。");
    private static DateTimeOffset? StartTime(System.Runtime.InteropServices.ComTypes.FILETIME time)
    {
        long value = ((long)(uint)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;
        try { return value > 0 ? new DateTimeOffset(DateTime.FromFileTimeUtc(value)) : null; }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    // https://learn.microsoft.com/windows/win32/api/restartmanager/ns-restartmanager-rm_process_info
    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int ProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME StartTime;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string AppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ServiceName;
        public uint ApplicationType;
        public uint AppStatus;
        public uint SessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmStartSession(out uint session, uint flags, StringBuilder key);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmRegisterResources(uint session, uint fileCount,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] files,
        uint applicationCount, IntPtr applications, uint serviceCount, IntPtr services);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmGetList(uint session, out uint needed, ref uint count,
        [In, Out] RmProcessInfo[]? processes, out uint rebootReasons);
    [DllImport("rstrtmgr.dll")]
    private static extern uint RmEndSession(uint session);
}
