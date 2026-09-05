using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed class BrokerMutationLease : IDisposable
{
    private const string LockFileName = "broker-mutation.lock";
    private readonly FileStream _stream;

    private BrokerMutationLease(FileStream stream)
    {
        _stream = stream;
    }

    public static bool TryAcquire(out BrokerMutationLease? lease)
    {
        string path = Path.Combine(AppPaths.BrokerTemporaryRoot, LockFileName);
        return TryAcquireCore(path, protectAcl: true, out lease);
    }

    internal static bool TryAcquireForTesting(string path, out BrokerMutationLease? lease) =>
        TryAcquireCore(path, protectAcl: false, out lease);

    private static bool TryAcquireCore(string path, bool protectAcl, out BrokerMutationLease? lease)
    {
        lease = null;
        string fullPath = Path.GetFullPath(path);
        if (Directory.Exists(fullPath) || Validation.ContainsReparsePoint(Path.GetDirectoryName(fullPath)!))
            throw new UnauthorizedAccessException("Broker 全局操作锁路径不安全。");

        bool existing = File.Exists(fullPath);
        if (existing)
        {
            if (Validation.ContainsReparsePoint(fullPath))
                throw new UnauthorizedAccessException("Broker 全局操作锁是重解析点。");
            if (protectAcl) MachineStateSecurity.EnsureProtectedPath(fullPath);
        }

        FileStream stream;
        try
        {
            stream = new FileStream(
                fullPath,
                existing ? FileMode.Open : FileMode.CreateNew,
                existing ? FileAccess.Read : FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                existing ? FileOptions.None : FileOptions.WriteThrough);
        }
        catch (IOException)
        {
            return false;
        }

        try
        {
            if (protectAcl && !existing) MachineStateSecurity.ProtectBrokerStateFile(fullPath);
            if (Validation.ContainsReparsePoint(fullPath))
                throw new UnauthorizedAccessException("Broker 全局操作锁在打开时发生重定向。");
            lease = new BrokerMutationLease(stream);
            return true;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        _stream.Dispose();
    }
}
