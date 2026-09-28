using SteamSentinel.Core.Reporting;
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
            throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerMutationLease.TryAcquireCore.01"), sourceText => new UnauthorizedAccessException(sourceText));

        bool existing = File.Exists(fullPath);
        if (existing)
        {
            if (Validation.ContainsReparsePoint(fullPath))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerMutationLease.TryAcquireCore.02"), sourceText => new UnauthorizedAccessException(sourceText));
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
        catch (IOException ex) when (IsContention(ex, creating: !existing))
        {
            return false;
        }

        try
        {
            if (protectAcl && !existing) MachineStateSecurity.ProtectBrokerStateFile(fullPath);
            if (Validation.ContainsReparsePoint(fullPath))
                throw MessageExceptions.Create(MessageText.Create("Backend.Broker.BrokerMutationLease.TryAcquireCore.03"), sourceText => new UnauthorizedAccessException(sourceText));
            lease = new BrokerMutationLease(stream);
            return true;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    internal static bool IsContention(IOException exception, bool creating) =>
        // Preserve unrelated I/O failures for the error channel; they do not prove
        // another Broker owns the lease. Compare full HRESULTs, not only low bits.
        exception.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021) ||
        creating && (exception.HResult is unchecked((int)0x80070050) or unchecked((int)0x800700B7));

    public void Dispose()
    {
        _stream.Dispose();
    }
}
