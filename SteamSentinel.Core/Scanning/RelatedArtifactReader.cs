using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

/// <summary>A read-only, deny-write/delete handle. It never grants mutation or follows a redirected path.</summary>
internal static class RelatedArtifactReader
{
    internal static FileStream Open(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(path)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.Open.01"), sourceText => new UnauthorizedAccessException(sourceText));
        string requested = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFile(requested, 0x80000000, 1, IntPtr.Zero, 3,
            0x00200000 | 0x08000000 | 0x40000000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error(); handle.Dispose();
            throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.Open.02"), sourceText => new Win32Exception(error, sourceText));
        }
        try
        {
            ValidatePath(handle, requested);
            return new FileStream(handle, FileAccess.Read, 128 * 1024, isAsync: true);
        }
        catch { handle.Dispose(); throw; }
    }

    internal static void ValidatePath(SafeFileHandle handle, string requested)
    {
        if (!GetFileInformationByHandleEx(handle, 9, out AttributeTag attributes, 8) || (attributes.Attributes & 0x400) != 0)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ValidatePath.01"), sourceText => new UnauthorizedAccessException(sourceText));
        char[] buffer = new char[Math.Min(32768, Math.Max(512, requested.Length + 16))];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length >= buffer.Length && length < 32768)
        {
            buffer = new char[length + 1];
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        }
        if (length == 0 || length >= buffer.Length) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ValidatePath.02"), sourceText => new IOException(sourceText));
        string final = new(buffer, 0, (int)length);
        if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
        if (!requested.Equals(final, StringComparison.OrdinalIgnoreCase) || !ContentDiscovery.IsLocalSafePath(requested))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ValidatePath.03"), sourceText => new UnauthorizedAccessException(sourceText));
    }

    internal static bool IsProtected(string path) =>
        new[] { Environment.GetFolderPath(Environment.SpecialFolder.Windows), AppContext.BaseDirectory,
            AppPaths.MachineStateRoot, AppPaths.UserStateRoot }.Any(root => !string.IsNullOrWhiteSpace(root) && ContentDiscovery.IsWithin(path, root));

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTag { public uint Attributes; public uint Tag; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out AttributeTag info, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint size, uint flags);
}

public sealed record RelatedTaskSnapshot(string TaskName, string Sha256, IReadOnlyList<string> Commands, int ByteLength,
    IReadOnlyList<string> Invocations);

/// <summary>Only task XML has this narrow Windows-directory read exception; it never authorizes a file action.</summary>
public static class RelatedTaskSnapshotReader
{
    public const int MaximumBytes = 2 * 1024 * 1024;
    public static string TaskRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");

    public static Task<RelatedTaskSnapshot> ReadAsync(string taskName, CancellationToken token = default) =>
        ReadUnderRootAsync(taskName, TaskRoot, token);

    internal static async Task<RelatedTaskSnapshot> ReadUnderRootAsync(string taskName, string root, CancellationToken token,
        Action<int>? bytesRead = null, int maximumBytes = MaximumBytes)
    {
        token.ThrowIfCancellationRequested();
        if (!Validation.TryNormalizeScheduledTaskName(taskName, out string normalized) ||
            normalized.IndexOfAny(['*', '?', '"', '<', '>', '|']) >= 0 || taskName.StartsWith(@"\\", StringComparison.Ordinal))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.01"), sourceText => new InvalidDataException(sourceText));
        string path = Path.GetFullPath(Path.Combine(root, normalized.TrimStart('\\')));
        if (!ContentDiscovery.IsWithin(path, root) || path.Equals(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.02"), sourceText => new InvalidDataException(sourceText));
        await using FileStream stream = RelatedArtifactReader.Open(path);
        if (stream.Length > Math.Min(MaximumBytes, maximumBytes)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.03"), sourceText => new InvalidDataException(sourceText));
        byte[] bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        bytesRead?.Invoke(bytes.Length);
        token.ThrowIfCancellationRequested();
        using MemoryStream input = new(bytes, writable: false);
        using XmlReader reader = XmlReader.Create(input, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumBytes,
            MaxCharactersFromEntities = 1024
        });
        XDocument document = XDocument.Load(reader);
        if (document.Root?.Name.LocalName != "Task") throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.04"), sourceText => new InvalidDataException(sourceText));
        XElement[] actions = document.Root.Elements().Where(e => e.Name.LocalName == "Actions")
            .SelectMany(e => e.Elements()).Where(e => e.Name.LocalName == "Exec").Take(65).ToArray();
        if (actions.Any(a => a.Elements().Count(c => c.Name.LocalName == "Command") != 1 ||
            a.Elements().Count(c => c.Name.LocalName == "Arguments") > 1)) throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.05"), sourceText => new InvalidDataException(sourceText));
        string[] commands = actions
            .Select(e => string.Join(" ", e.Elements().Where(c => c.Name.LocalName is "Command" or "Arguments").Select(c => c.Value))).ToArray();
        if (commands.Length > 64 || commands.Any(c => c.Length > 32768))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.RelatedArtifactReader.ReadUnderRootAsync.06"), sourceText => new InvalidDataException(sourceText));
        string[] invocations = actions.Select(a =>
        {
            string executable = a.Elements().Single(c => c.Name.LocalName == "Command").Value.Trim();
            string arguments = a.Elements().FirstOrDefault(c => c.Name.LocalName == "Arguments")?.Value ?? "";
            return "\"" + executable.Trim('"') + "\"" + (arguments.Length > 0 ? " " + arguments : "");
        }).ToArray();
        return new(normalized, Hashing.Sha256Bytes(bytes), commands, bytes.Length, invocations);
    }
}
