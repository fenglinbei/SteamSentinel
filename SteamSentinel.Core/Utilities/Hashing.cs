using System.Buffers;
using System.Security.Cryptography;

namespace SteamSentinel.Core.Utilities;

public static class Hashing
{
    public static async Task<string> Sha256FileExclusiveAsync(
        string path,
        CancellationToken cancellationToken = default,
        long maximumBytes = long.MaxValue)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await Sha256StreamAsync(stream, cancellationToken, maximumBytes: maximumBytes).ConfigureAwait(false);
    }

    public static async Task<string> Sha256FileAsync(
        string path,
        CancellationToken cancellationToken = default,
        Action<int>? bytesRead = null,
        long maximumBytes = long.MaxValue)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        return await Sha256StreamAsync(stream, cancellationToken, bytesRead, maximumBytes);
    }

    public static async Task<string> Sha256StreamAsync(
        Stream stream,
        CancellationToken cancellationToken = default,
        Action<int>? bytesRead = null,
        long maximumBytes = long.MaxValue)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maximumBytes);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long total = 0;
        try
        {
            while (true)
            {
                int requested = maximumBytes == long.MaxValue ? buffer.Length :
                    (int)Math.Min(buffer.Length, maximumBytes - total + 1);
                int read = await stream.ReadAsync(buffer.AsMemory(0, requested), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > maximumBytes)
                    throw new InvalidDataException($"文件在读取期间超过 {maximumBytes} 字节哈希上限。");
                hash.AppendData(buffer, 0, read);
                bytesRead?.Invoke(read);
            }

            return Convert.ToHexString(hash.GetHashAndReset());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    public static string Sha256Bytes(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes));
}
