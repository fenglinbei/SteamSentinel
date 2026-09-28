using System.Runtime.InteropServices;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

public static class ScanResourcePlanner
{
    private const long MiB = 1024 * 1024;
    [StructLayout(LayoutKind.Sequential)]
    private struct PerformanceInformation
    {
        public uint Size;
        public nuint CommitTotal, CommitLimit, CommitPeak, PhysicalTotal, PhysicalAvailable,
            SystemCache, KernelTotal, KernelPaged, KernelNonpaged, PageSize;
        public uint HandleCount, ProcessCount, ThreadCount;
    }
    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPerformanceInfo(out PerformanceInformation information, uint size);

    public static ScanMachineResources Capture(string temporaryDirectory)
    {
        long available = -1, commit = -1, total = -1;
        // GlobalMemoryStatusEx's available page file is capped by this process's Job.
        // Capacity must use system commit; the per-process Job headroom is checked separately.
        if (OperatingSystem.IsWindows() && GetPerformanceInfo(out PerformanceInformation memory,
            (uint)Marshal.SizeOf<PerformanceInformation>()) && memory.PageSize > 0 && memory.CommitLimit >= memory.CommitTotal)
        {
            try
            {
                available = checked((long)checked(memory.PhysicalAvailable * memory.PageSize));
                total = checked((long)checked(memory.PhysicalTotal * memory.PageSize));
                commit = checked((long)checked((memory.CommitLimit - memory.CommitTotal) * memory.PageSize));
            }
            catch (OverflowException) { available = commit = total = -1; }
        }
        long disk = -1;
        string volume = string.Empty;
        try { volume = Path.GetPathRoot(Path.GetFullPath(temporaryDirectory)) ?? string.Empty; disk = new DriveInfo(volume).AvailableFreeSpace; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        return new(available, commit, total, disk, Environment.ProcessorCount, DateTimeOffset.UtcNow, volume);
    }

    public static int ParallelFiles(ScanMachineResources machine, ScanPerformanceMode mode)
    {
        if (!machine.IsUsable || mode == ScanPerformanceMode.LowImpact) return 1;
        int memorySlots = (int)Math.Clamp(AvailableForScan(machine) / (128 * MiB), 1, 4);
        int cpuSlots = Math.Max(1, machine.LogicalProcessors / 2);
        int slots = Math.Min(Math.Min(memorySlots, cpuSlots), mode == ScanPerformanceMode.HighThroughput ? 4 : 2);
        return slots >= 4 ? 4 : slots >= 2 ? 2 : 1;
    }

    private static long AvailableForScan(ScanMachineResources machine) => Math.Min(
        machine.AvailableMemoryBytes - Math.Max(1024 * MiB, machine.TotalMemoryBytes / 8),
        machine.CommitHeadroomBytes - 1024 * MiB);

    public static ScanResourceProposal Refresh(ScanResourceProposal proposal)
    {
        ScanMachineResources machine = Capture(proposal.Machine.TemporaryVolume);
        bool fits = machine.IsUsable && Math.Max(0, proposal.EstimatedPrivateBytes - proposal.Request.PrivateMemoryBytes) <=
            AvailableForScan(machine) &&
            proposal.AdditionalTemporaryBytes <= machine.TemporaryFreeBytes - proposal.ReservedDiskBytes;
        ResourceAssessmentKind assessment = !machine.IsUsable ? ResourceAssessmentKind.Unknown :
            fits && proposal.Changes.Count > 0 ? ResourceAssessmentKind.EstimatedAvailable : ResourceAssessmentKind.Insufficient;
        return proposal with { Machine = machine, Assessment = assessment, ReasonCode = assessment switch
        { ResourceAssessmentKind.EstimatedAvailable => "resource.estimated_available", ResourceAssessmentKind.Unknown => "resource.capacity_unknown", _ => "resource.capacity_insufficient" } };
    }

    public static ScanResourceProposal Propose(ScanOptions options, ScanLimitRequest request, ScanMachineResources machine)
    {
        request.Validate();
        if (ScanLimitAccess.Get(options, request.LimitKey) != request.CurrentLimit) throw new InvalidDataException("Stale resource request.");
        List<ScanLimitChange> changes = [];
        long temporary = 0, peak = request.PrivateMemoryBytes;
        void Increase(string key, long minimum)
        {
            long current = ScanLimitAccess.Get(options, key);
            if (minimum <= current) return;
            ScanLimitDefinition field = ScanLimitAccess.Definition(key);
            decimal increment = request.DemandKnown ? minimum : Math.Max((decimal)minimum, current + Math.Max(1m, current / 2m));
            decimal rounded = field.Scale > 1 ? decimal.Ceiling(increment / MiB) * MiB : decimal.Ceiling(increment);
            long after = checked((long)rounded);
            ScanLimitChange change = new(key, current, after);
            ScanLimitAccess.ValidateChange(change);
            int existing = changes.FindIndex(c => c.LimitKey == key);
            if (existing < 0) changes.Add(change);
            else if (after > changes[existing].After) changes[existing] = change;
        }
        try
        {
            Increase(request.LimitKey, request.RequiredMinimum);
            if (request.LimitKey == "ContainerLimits.MaximumEntryBytes")
            {
                temporary = request.RequiredMinimum;
                Increase("ContainerLimits.MaximumTemporaryBytes", checked(request.TemporaryBytes + temporary));
                Increase("ContainerLimits.MaximumExpandedBytes", checked(request.ExpandedBytes + temporary));
                Increase("ContainerLimits.MaximumWorkBytes", checked(request.WorkBytes + temporary * 2));
            }
            if (request.LimitKey == "ContainerLimits.MaximumTemporaryBytes")
                temporary = Math.Max(0, changes[0].After - request.TemporaryBytes);
            if (request.LimitKey == "MaximumAmsiBytes")
            {
                peak = checked(request.PrivateMemoryBytes + request.RequiredMinimum * 2 + 128 * MiB);
                Increase("MaximumWorkerMemoryBytes", checked(peak / 3 * 4 + 64 * MiB));
            }
            if (request.LimitKey == "MaximumStringScanBytes") peak = checked(peak + 64 * MiB);
            if (request.LimitKey == "MaximumWorkerMemoryBytes") peak = Math.Max(peak, changes[0].After / 4 * 3);
            if (request.LimitKey is "MaximumReportRecords" or "ContainerLimits.MaximumNodes" or "RangeLimits.MaximumRecords" or "RangeLimits.MaximumZipEntries"
                or "MaximumFiles" or "ContainerLimits.MaximumEntries" or "ContainerLimits.MaximumMetadataAttempts"
                or "ContainerLimits.MaximumDirectoryCandidates" or "RangeLimits.MaximumCandidates")
                peak = checked(peak + (changes[0].After - request.CurrentLimit) * 4096);
            if (request.LimitKey == "ContainerLimits.MaximumVolumes")
                peak = checked(peak + (changes[0].After - request.CurrentLimit) * 256 * 1024);
            if (request.LimitKey == "MaximumReportTextCharacters")
                peak = checked(peak + (changes[0].After - request.CurrentLimit) * 4);
            if (request.LimitKey is "RangeLimits.MaximumHeaderBytes" or "RangeLimits.MaximumSignatureSearchBytes" or "RangeLimits.MaximumSfxConfigurationBytes")
                peak = checked(peak + changes[0].After * 4);
            if (peak > request.PrivateMemoryBytes && request.LimitKey != "MaximumWorkerMemoryBytes")
                Increase("MaximumWorkerMemoryBytes", checked(peak / 3 * 4 + 64 * MiB));
            long diskReserve = Math.Max(1024 * MiB, options.ContainerLimits?.ReservedDiskBytes ?? 0);
            bool fits = machine.IsUsable && Math.Max(0, peak - request.PrivateMemoryBytes) <= AvailableForScan(machine) &&
                temporary <= machine.TemporaryFreeBytes - diskReserve;
            return new(request, machine, !machine.IsUsable ? ResourceAssessmentKind.Unknown : fits ? ResourceAssessmentKind.EstimatedAvailable : ResourceAssessmentKind.Insufficient,
                !machine.IsUsable ? "resource.capacity_unknown" : fits ? "resource.estimated_available" : "resource.capacity_insufficient", changes, temporary, peak, diskReserve);
        }
        catch (Exception ex) when (ex is OverflowException or ArgumentOutOfRangeException or InvalidDataException)
        {
            return new(request, machine, ResourceAssessmentKind.Insufficient, "resource.representation_limit", [], temporary, peak);
        }
    }
}
