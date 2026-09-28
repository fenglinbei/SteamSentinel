using SteamSentinel.Core.Reporting;
using System.Reflection;
using SharpCompress.Common;

namespace SteamSentinel.Core.Inspection;

public static partial class ArchiveIntegrity
{
    /// <summary>Prepare before reading. Complete only after EOF and before disposing the decoder stream.</summary>
    public static ArchiveIntegrityEntryVerifier Begin(ArchiveVolumeSession session, IEntry entry)
    {
        ArgumentNullException.ThrowIfNull(session); ArgumentNullException.ThrowIfNull(entry);
        session.RequireCurrentEntry(entry);
        ArchiveIntegrityEntryVerifier verifier = BeginCore(session, entry);
        if (!entry.IsDirectory) verifier.OnVerified(() => session.MarkEntryVerified(entry));
        return verifier;
    }

    private static ArchiveIntegrityEntryVerifier BeginCore(ArchiveVolumeSession session, IEntry entry)
    {
        if (entry.IsDirectory) return new(new(true, false, 0, 0, false, MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.01")));
        switch (session.Plan.Format)
        {
            case ArchiveVolumeFormat.Zip:
                string key = (entry.Key ?? "").Replace('\\', '/');
                ArchiveIntegrityZipMember? zip = session.FindZipMember(key, entry.Size, unchecked((uint)entry.Crc), entry.IsEncrypted);
                if (zip is null) return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.02"));
                if (zip.Encrypted && session.Password is null) return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.03"));
                // AE-2 has an authenticated ciphertext and deliberately no plaintext CRC. Ordinary
                // ZIP and AE-1 retain valid CRC32 values including zero.
                return new(new(true, zip.AesVersion != 2, zip.Crc, zip.Size,
                    zip.Encrypted && zip.Size > 0, zip.AesVersion == 2 ? MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.04") : MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.05")));
            case ArchiveVolumeFormat.Rar:
                if (session.RarIntegrity is null) return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.06"));
                ArchiveIntegrityRarVerifier rar = BeginRar(entry, session.RarIntegrity, session.Password);
                return new(rar.Requirement, rar);
            case ArchiveVolumeFormat.SevenZip:
                return SevenZip(entry);
            default: return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.BeginCore.07"));
        }
    }

    private static ArchiveIntegrityEntryVerifier SevenZip(IEntry entry)
    {
        try
        {
            // The dependency is locked to 0.50.4. Public IEntry.Crc erases nullable CRC
            // presence, so inspect only these documented source fields and fail closed
            // if the package's shape changes. No decoder state is modified.
            object? part = FindProperty(entry.GetType(), "FilePart")?.GetValue(entry);
            if (part?.GetType().FullName != "SharpCompress.Common.SevenZip.SevenZipFilePart")
                return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.01"));
            object? header = FindProperty(part.GetType(), "Header")?.GetValue(part);
            if (header?.GetType().FullName != "SharpCompress.Common.SevenZip.CFileItem")
                return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.02"));
            PropertyInfo? crcField = header.GetType().GetProperty("Crc", BindingFlags.Instance | BindingFlags.Public);
            PropertyInfo? streamField = header.GetType().GetProperty("HasStream", BindingFlags.Instance | BindingFlags.Public);
            PropertyInfo? antiField = header.GetType().GetProperty("IsAnti", BindingFlags.Instance | BindingFlags.Public);
            if (crcField?.PropertyType != typeof(uint?) || streamField?.PropertyType != typeof(bool) || antiField?.PropertyType != typeof(bool))
                return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.03"));
            if ((bool)antiField.GetValue(header)!) return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.04"));
            uint? crc = (uint?)crcField.GetValue(header);
            bool hasStream = (bool)streamField.GetValue(header)!;
            if (!hasStream && entry.Size == 0) return new(new(true, true, 0, 0, false, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.05")));
            if (!crc.HasValue) return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.06"));
            return new(new(true, true, crc.Value, entry.Size, entry.IsEncrypted && entry.Size > 0, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.07")));
        }
        catch (Exception exception) when (exception is TargetInvocationException or ArgumentException or InvalidCastException or MemberAccessException)
        { return Unsupported(entry, MessageText.Create("Backend.Core.ArchiveIntegrity.SevenZip.08")); }
    }

    private static PropertyInfo? FindProperty(Type type, string name)
    {
        for (Type? current = type; current is not null; current = current.BaseType)
        {
            PropertyInfo? property = current.GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            if (property is not null) return property;
        }
        return null;
    }
    private static ArchiveIntegrityEntryVerifier Unsupported(IEntry entry, MessageText detail) =>
        new(new(false, false, 0, entry.Size, false, detail));
}

public sealed class ArchiveIntegrityEntryVerifier : IDisposable
{
    private readonly ArchiveIntegrityRarVerifier? _rar;
    private bool _completed;
    private bool _disposed;
    private Action? _onVerified;
    public ArchiveIntegrityRequirement Requirement { get; }
    public bool CanValidatePassword => _completed && Requirement.CanValidatePassword;
    internal ArchiveIntegrityEntryVerifier(ArchiveIntegrityRequirement requirement, ArchiveIntegrityRarVerifier? rar = null)
    { Requirement = requirement; _rar = rar; }
    internal void OnVerified(Action callback) => _onVerified = callback;

    public void Complete(Stream decodedStream, long copied, uint actualCrc32)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed) throw MessageExceptions.Create(MessageText.Create("Backend.Core.ArchiveIntegrity.Complete.01"), sourceText => new InvalidOperationException(sourceText));
        if (_rar is not null) _rar.Complete(decodedStream, copied, actualCrc32);
        else ArchiveIntegrity.Complete(Requirement, copied, actualCrc32);
        _onVerified?.Invoke();
        _completed = true;
    }
    public void Dispose()
    {
        if (_disposed) return; _disposed = true; _rar?.Dispose();
    }
}
