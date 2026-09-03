using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SteamSentinel.App.Native;

internal sealed class JobObject : IDisposable
{
    private readonly SafeJobHandle _handle;

    public JobObject(long processMemoryLimitBytes = 1024L * 1024 * 1024)
    {
        _handle = CreateJobObject(IntPtr.Zero, null);
        if (_handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());

        JobObjectExtendedLimitInformation information = new();
        information.BasicLimitInformation.LimitFlags =
            JobObjectLimitKillOnJobClose |
            JobObjectLimitActiveProcess |
            JobObjectLimitProcessMemory |
            JobObjectLimitDieOnUnhandledException;
        information.BasicLimitInformation.ActiveProcessLimit = 1;
        information.ProcessMemoryLimit = (UIntPtr)processMemoryLimitBytes;

        int size = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(information, pointer, false);
            if (!SetInformationJobObject(_handle, 9, pointer, (uint)size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }

        JobObjectBasicUiRestrictions uiRestrictions = new()
        {
            UiRestrictionsClass = JobObjectUiLimitHandles |
                                  JobObjectUiLimitReadClipboard |
                                  JobObjectUiLimitWriteClipboard |
                                  JobObjectUiLimitSystemParameters |
                                  JobObjectUiLimitDisplaySettings |
                                  JobObjectUiLimitExitWindows
        };
        int uiSize = Marshal.SizeOf<JobObjectBasicUiRestrictions>();
        IntPtr uiPointer = Marshal.AllocHGlobal(uiSize);
        try
        {
            Marshal.StructureToPtr(uiRestrictions, uiPointer, false);
            if (!SetInformationJobObject(_handle, 4, uiPointer, (uint)uiSize))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeHGlobal(uiPointer);
        }
    }

    public void Assign(Process process)
        => Assign(process.Handle);

    public void Assign(IntPtr processHandle)
    {
        if (!AssignProcessToJobObject(_handle, processHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Dispose() => _handle.Dispose();

    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectUiLimitHandles = 0x00000001;
    private const uint JobObjectUiLimitReadClipboard = 0x00000002;
    private const uint JobObjectUiLimitWriteClipboard = 0x00000004;
    private const uint JobObjectUiLimitSystemParameters = 0x00000008;
    private const uint JobObjectUiLimitDisplaySettings = 0x00000010;
    private const uint JobObjectUiLimitExitWindows = 0x00000080;

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicUiRestrictions
    {
        public uint UiRestrictionsClass;
    }

    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeJobHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeJobHandle CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeJobHandle job, int informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeJobHandle job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
