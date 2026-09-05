namespace SteamSentinel.Core.Utilities;

public static class AtomicFile
{
    public static async Task WriteAsync(string destination, Func<FileStream, Task> write, CancellationToken token = default)
    {
        string full = Path.GetFullPath(destination);
        string directory = Path.GetDirectoryName(full) ?? throw new IOException("输出文件没有父目录。");
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(full)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (FileStream output = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                token.ThrowIfCancellationRequested();
                await write(output).ConfigureAwait(false);
                await output.FlushAsync(token).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            token.ThrowIfCancellationRequested();
            File.Move(temporary, full, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
