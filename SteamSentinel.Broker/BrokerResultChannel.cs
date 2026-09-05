using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed class BrokerResultChannel : IAsyncDisposable
{
    private readonly FileStream _stream;
    private bool _writeAttempted;

    private BrokerResultChannel(FileStream stream)
    {
        _stream = stream;
    }

    public bool HasWritten { get; private set; }
    public bool CanWrite => !_writeAttempted;

    public static BrokerResultChannel Create(string path, string requestedBySid)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.ResultsRoot));
        if (!fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(fullPath).StartsWith("result-", StringComparison.OrdinalIgnoreCase) ||
            !fullPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
            Validation.ContainsReparsePoint(Path.GetDirectoryName(fullPath)!))
        {
            throw new UnauthorizedAccessException("Broker 结果通道路径无效。");
        }

        return CreateCore(fullPath, requestedBySid, protectAcl: true);
    }

    internal static BrokerResultChannel CreateForTesting(string path) =>
        CreateCore(Path.GetFullPath(path), requestedBySid: string.Empty, protectAcl: false);

    private static BrokerResultChannel CreateCore(string fullPath, string requestedBySid, bool protectAcl)
    {
        FileStream stream = new(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        try
        {
            if (protectAcl) MachineStateSecurity.ProtectResultFile(fullPath, requestedBySid);
            return new BrokerResultChannel(stream);
        }
        catch
        {
            stream.Dispose();
            try { File.Delete(fullPath); } catch { }
            throw;
        }
    }

    public async Task WriteAsync(RemediationRunResult result, CancellationToken cancellationToken = default)
    {
        if (_writeAttempted) throw new InvalidOperationException("Broker 结果通道只能写入一次。");
        _writeAttempted = true;
        _stream.Position = 0;
        _stream.SetLength(0);
        await JsonSerializer.SerializeAsync(_stream, result, JsonFile.Options, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        _stream.Flush(flushToDisk: true);
        HasWritten = true;
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}
