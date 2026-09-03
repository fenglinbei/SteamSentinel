using System.Buffers;
using System.Security.Cryptography;

namespace SteamSentinel.Core.Utilities;

public static class Hashing
{
    public static async Task<string> Sha256FileAsync(
        string path,
        CancellationToken cancellationToken = default,
        Action<int>? bytesRead = null)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        return await Sha256StreamAsync(stream, cancellationToken, bytesRead);
    }

    public static async Task<string> Sha256StreamAsync(
        Stream stream,
        CancellationToken cancellationToken = default,
        Action<int>? bytesRead = null)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        try
        {
            while (true)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

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
