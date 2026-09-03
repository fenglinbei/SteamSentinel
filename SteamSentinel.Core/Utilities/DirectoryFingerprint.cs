using System.Security.Cryptography;
using System.Text;

namespace SteamSentinel.Core.Utilities;

public static class DirectoryFingerprint
{
    public static async Task<string> ComputeAsync(string root, CancellationToken cancellationToken = default)
        => (await CaptureAsync(root, cancellationToken).ConfigureAwait(false)).Sha256;

    public static async Task<DirectoryFingerprintSnapshot> CaptureAsync(
        string root,
        CancellationToken cancellationToken = default)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Directory.Exists(fullRoot)) throw new DirectoryNotFoundException(fullRoot);
        if (Validation.ContainsReparsePoint(fullRoot))
            throw new UnauthorizedAccessException("目录路径包含重解析点，无法建立安全指纹。");

        string[] entries = EnumerateWithoutFollowingReparsePoints(fullRoot)
            .OrderBy(path => Path.GetRelativePath(fullRoot, path), StringComparer.OrdinalIgnoreCase)
            .ToArray();

        using IncrementalHash aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        List<DirectoryFingerprintEntry> snapshotEntries = [];
        foreach (string entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"目录树包含重解析点：{entry}");

            string relative = Path.GetRelativePath(fullRoot, entry).Replace(Path.DirectorySeparatorChar, '/');
            if ((attributes & FileAttributes.Directory) != 0)
            {
                Append(aggregate, $"D\0{relative}\0");
                snapshotEntries.Add(new DirectoryFingerprintEntry(relative, true, 0, null));
                continue;
            }

            FileInfo info = new(entry);
            string hash = await Hashing.Sha256FileAsync(entry, cancellationToken).ConfigureAwait(false);
            Append(aggregate, $"F\0{relative}\0{info.Length}\0{hash}\0");
            snapshotEntries.Add(new DirectoryFingerprintEntry(relative, false, info.Length, hash));
        }

        return new DirectoryFingerprintSnapshot(
            Convert.ToHexString(aggregate.GetHashAndReset()),
            snapshotEntries);
    }

    private static void Append(IncrementalHash hash, string value) =>
        hash.AppendData(Encoding.UTF8.GetBytes(value));

    private static IEnumerable<string> EnumerateWithoutFollowingReparsePoints(string root)
    {
        Stack<string> pending = new();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            if (Validation.ContainsReparsePoint(directory))
                throw new UnauthorizedAccessException($"目录树包含重解析点：{directory}");
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"目录树包含重解析点：{entry}");
                yield return entry;
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
        }
    }
}

public sealed record DirectoryFingerprintSnapshot(
    string Sha256,
    IReadOnlyList<DirectoryFingerprintEntry> Entries);

public sealed record DirectoryFingerprintEntry(
    string RelativePath,
    bool IsDirectory,
    long Length,
    string? Sha256);
