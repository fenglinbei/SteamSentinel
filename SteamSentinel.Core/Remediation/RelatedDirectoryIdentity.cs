using SteamSentinel.Core.Reporting;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

/// <summary>Same wire fingerprint as DirectoryFingerprint, with explicit relation-preview read limits.</summary>
internal static class RelatedDirectoryIdentity
{
    internal static async Task<string> ComputeAsync(string path, CancellationToken token)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!Validation.IsSafeExactTarget(root) || !ContentDiscovery.IsLocalSafePath(root) ||
            RelatedArtifactReader.IsProtected(root) || !Directory.Exists(root)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.01"), sourceText => new InvalidDataException(sourceText));
        List<(string Path, bool Directory)> entries = [];
        Stack<(string Path, int Depth)> pending = new();
        pending.Push((root, 0));
        while (pending.TryPop(out var item))
        {
            token.ThrowIfCancellationRequested();
            if (!ContentDiscovery.IsLocalSafePath(item.Path)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.02"), sourceText => new InvalidDataException(sourceText));
            foreach (string child in Directory.EnumerateFileSystemEntries(item.Path))
            {
                token.ThrowIfCancellationRequested();
                if (entries.Count >= 2000 || item.Depth >= 16) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.03"), sourceText => new InvalidDataException(sourceText));
                if (!ContentDiscovery.IsLocalSafePath(child)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.04"), sourceText => new InvalidDataException(sourceText));
                bool directory = (File.GetAttributes(child) & FileAttributes.Directory) != 0;
                entries.Add((child, directory));
                if (directory) pending.Push((child, item.Depth + 1));
            }
        }
        long bytes = 0;
        using IncrementalHash aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in entries.OrderBy(e => Path.GetRelativePath(root, e.Path), StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();
            string relative = Path.GetRelativePath(root, item.Path).Replace(Path.DirectorySeparatorChar, '/');
            if (item.Directory)
            {
                if (!ContentDiscovery.IsLocalSafePath(item.Path)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.05"), sourceText => new InvalidDataException(sourceText));
                aggregate.AppendData(Encoding.UTF8.GetBytes($"D\0{relative}\0"));
                continue;
            }
            await using FileStream stream = RelatedArtifactReader.Open(item.Path);
            long length = stream.Length;
            if (length > 256L * 1024 * 1024 || length > 512L * 1024 * 1024 - bytes)
                throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedDirectoryIdentity.ComputeAsync.06"), sourceText => new InvalidDataException(sourceText));
            string hash = await Hashing.Sha256StreamAsync(stream, token, count => bytes += count);
            aggregate.AppendData(Encoding.UTF8.GetBytes($"F\0{relative}\0{length}\0{hash}\0"));
        }
        return Convert.ToHexString(aggregate.GetHashAndReset());
    }
}
