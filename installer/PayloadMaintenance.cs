using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class MaintenanceException : IOException
{
    public string Code { get; private set; }
    public string RelativePath { get; private set; }
    public string[] Operations { get; internal set; }
    public MaintenanceException(string code, string path) : this(code, path, null) { }
    public MaintenanceException(string code, string path, string detail) : base(code + ": " + path +
        (String.IsNullOrEmpty(detail) ? "" : "; " + Bound(detail)))
    { Code = code; RelativePath = path; Operations = new string[0]; }
    static string Bound(string text)
    { return text.Substring(0, Math.Min(text.Length, 2048)).Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' '); }
}

public sealed class LegacyEntry
{
    public string RelativePath { get; private set; }
    public long Bytes { get; private set; }
    public string Sha256 { get; private set; }
    public LegacyEntry(string relativePath, long bytes, string sha256)
    { RelativePath = relativePath; Bytes = bytes; Sha256 = sha256; }
}

// Installer-only maintenance. The public production entry point has no install-root or catalog override.
public static class SteamSentinelPayloadMaintenance
{
    static readonly LegacyEntry[] Catalog = {
        new LegacyEntry("mscordaccore_amd64_amd64_10.0.1126.37416.dll", 1356632,
            "C1B92DA5356BB36F4AB55AA54B2D25A8A27518CF7A456EB4957DDFE94E2D428C"),
        new LegacyEntry("SIGNER.cer", 1022,
            "927392458711531A02B5DDF3AE170C79059EFCBBEE90AD3A453EFE939B2C2255"),
        new LegacyEntry(@"Assets\App.ico", 156459,
            "162F9AC661707279CAE17A8DD86348BE71486989DE4917FFE238BE3DF404837A"),
        new LegacyEntry(@"Assets\App.png", 1317522,
            "7B72DC146BF3D958C89B8106AE8F1894A8AA07CC896E11D54355A026A0FBCF1C")
    };
    static readonly string[] Trusted = { "S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
    static readonly HashSet<string> InstallerMetadata = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "SHA256SUMS.txt", "unins000.exe", "unins000.dat", "unins000.msg"
    };
    const uint ReadControl = 0x20000, ReadAttributes = 0x80, GenericRead = 0x80000000, DeleteAccess = 0x10000;
    const uint OpenExisting = 3, OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000;
    const uint DirectoryAttribute = 0x10, ReparseAttribute = 0x400;
    const int MaximumEntries = 10000;
    const long MaximumFileBytes = 512L * 1024 * 1024, MaximumTreeBytes = 2L * 1024 * 1024 * 1024;
    const int WriteMask = 2 | 4 | 16 | 256 | 65536 | 64 | 262144 | 524288 | 0x10000000 | 0x40000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFileAttributes(string path);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref Disposition info, uint length);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    [StructLayout(LayoutKind.Sequential)]
    struct FileInfoNative {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Disposition { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

    sealed class HeldFile : IDisposable
    {
        public readonly string Path, Relative;
        public readonly SafeFileHandle Handle;
        public readonly FileStream Stream;
        public readonly bool Directory, Metadata, CheckPermissions;
        public readonly FileInfoNative Identity;
        public HeldFile(string path, string relative, bool directory, bool metadata, bool delete, string[] trusted, bool checkPermissions = true)
        {
            Path = path; Relative = relative; Directory = directory; Metadata = metadata; CheckPermissions = checkPermissions;
            uint access = ReadControl | ReadAttributes | (directory || metadata ? 0 : GenericRead) | (delete ? DeleteAccess : 0);
            // Directories cannot be renamed; payload files cannot be written or replaced while held.
            // Inno owns and may still write its exact metadata files; these are never cleanup targets.
            uint share = directory || metadata ? 3U : 1U;
            Handle = CreateFile(path, access, share, IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics, IntPtr.Zero);
            if (Handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); Handle.Dispose();
                throw new MaintenanceException(error == 32 || error == 33 ? "FileBusy" : "AccessDenied", relative); }
            try {
                Identity = CheckIdentity(Handle, path, relative, directory);
                if (CheckPermissions) VerifyAcl(Handle, relative, trusted);
                if (!directory && !metadata) Stream = new FileStream(Handle, FileAccess.Read, 65536, false);
            } catch { Handle.Dispose(); throw; }
        }
        public long Length { get { return ((long)Identity.SizeHigh << 32) | Identity.SizeLow; } }
        public string Hash()
        {
            Stream.Position = 0;
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Stream)).Replace("-", "");
        }
        public void Recheck(string[] trusted)
        {
            FileInfoNative actual = CheckIdentity(Handle, Path, Relative, Directory);
            if (actual.VolumeSerial != Identity.VolumeSerial || actual.IndexHigh != Identity.IndexHigh ||
                actual.IndexLow != Identity.IndexLow || actual.Attributes != Identity.Attributes ||
                actual.SizeHigh != Identity.SizeHigh || actual.SizeLow != Identity.SizeLow)
                throw new MaintenanceException("FileChanged", Relative);
            if (CheckPermissions) VerifyAcl(Handle, Relative, trusted);
        }
        public void Dispose() { if (Stream != null) Stream.Dispose(); Handle.Dispose(); }
    }

    static FileInfoNative CheckIdentity(SafeFileHandle handle, string expected, string relative, bool directory)
    {
        FileInfoNative info;
        if (!GetFileInformationByHandle(handle, out info) || (info.Attributes & ReparseAttribute) != 0 ||
            ((info.Attributes & DirectoryAttribute) != 0) != directory || (!directory && info.Links != 1))
            throw new MaintenanceException("UnsafePath", relative);
        StringBuilder final = new StringBuilder(32768);
        uint n = GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
        if (n == 0 || n >= final.Capacity || !String.Equals(final.ToString(), @"\\?\" + expected, StringComparison.OrdinalIgnoreCase))
            throw new MaintenanceException("UnsafePath", relative);
        return info;
    }

    static void VerifyAcl(SafeFileHandle handle, string relative, string[] trusted)
    {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint error = GetSecurityInfo(handle, 1, 7, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) throw new MaintenanceException("UnsafePermissions", relative);
        try {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 65536) throw new MaintenanceException("UnsafePermissions", relative);
            byte[] bytes = new byte[(int)length]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0);
            if (security.Owner == null || Array.IndexOf(trusted, security.Owner.Value) < 0 || security.DiscretionaryAcl == null)
                throw new MaintenanceException("UnsafePermissions", relative);
            foreach (GenericAce entry in security.DiscretionaryAcl) {
                if ((entry.AceFlags & AceFlags.InheritOnly) != 0) continue;
                QualifiedAce ace = entry as QualifiedAce;
                if (ace == null) throw new MaintenanceException("UnsafePermissions", relative);
                if (ace.AceQualifier == AceQualifier.AccessAllowed && (ace.AccessMask & WriteMask) != 0 &&
                    (ace.IsCallback || Array.IndexOf(trusted, ace.SecurityIdentifier.Value) < 0))
                    throw new MaintenanceException("UnsafePermissions", relative);
            }
        } finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }

    static bool IsHash(string hash)
    {
        if (hash == null || hash.Length != 64) return false;
        foreach (char c in hash) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        return true;
    }
    static string RelativeName(string text)
    {
        if (String.IsNullOrEmpty(text) || text.Length > 240 || text[0] == '\\' || text[0] == '/' || text.IndexOf('/') >= 0)
            throw new MaintenanceException("InvalidManifest", "");
        foreach (char c in text) if (c < 32 || "<>:\"|?*".IndexOf(c) >= 0) throw new MaintenanceException("InvalidManifest", text);
        foreach (string part in text.Split('\\')) {
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal))
                throw new MaintenanceException("InvalidManifest", text);
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] >= '0' && stem[3] <= '9'))
                throw new MaintenanceException("InvalidManifest", text);
        }
        return text;
    }
    static MaintenanceException PathFailure(string code, string role, string input, string component, string final, int error)
    {
        return new MaintenanceException(code, role, "Stage=NormalizePath; Input=" + input +
            "; Component=" + component + "; Final=" + final + "; Win32=" + error);
    }
    static string FullLocal(string path, string role = "<path>")
    {
        // Validate before any Windows normalization: neither dot segments, device names nor
        // alternate streams become acceptable just because Win32 can resolve them.
        if (String.IsNullOrEmpty(path) || path.Length < 3 || path.Length >= 32760 ||
            !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) ||
            path[1] != ':' || path[2] != '\\' || path.IndexOf('/') >= 0 || path.IndexOf(':', 2) >= 0)
            throw PathFailure("UnsafePath", role, path, "<syntax>", "", 0);
        string text = path.Length > 3 && path.EndsWith("\\", StringComparison.Ordinal) ? path.Substring(0, path.Length - 1) : path;
        string[] parts = text.Length == 3 ? new string[0] : text.Substring(3).Split('\\');
        foreach (string part in parts) {
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal))
                throw PathFailure("UnsafePath", role, path, part, "", 0);
            foreach (char c in part) if (c < 32 || "<>:\"|?*".IndexOf(c) >= 0)
                throw PathFailure("UnsafePath", role, path, part, "", 0);
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) &&
                ((stem[3] >= '0' && stem[3] <= '9') || "\u00b9\u00b2\u00b3".IndexOf(stem[3]) >= 0)))
                throw PathFailure("UnsafePath", role, path, part, "", 0);
        }
        // Resolve each name through a real handle with OPEN_REPARSE_POINT. Every existing
        // parent stays pinned against rename until resolution finishes. A short alias is
        // accepted only for an ordinary direct child of that same physical parent.
        string current = text.Substring(0, 3);
        List<SafeFileHandle> pins = new List<SafeFileHandle>();
        try {
            for (int index = -1; index < parts.Length; index++) {
                string candidate = index < 0 ? current : System.IO.Path.Combine(current, parts[index]);
                SafeFileHandle handle = CreateFile(candidate, ReadAttributes, 3, IntPtr.Zero, OpenExisting,
                    OpenReparsePoint | BackupSemantics, IntPtr.Zero);
                if (handle.IsInvalid) {
                    int error = Marshal.GetLastWin32Error(); handle.Dispose();
                    if (index >= 0 && (error == 2 || error == 3)) {
                        // Fresh installation: only a syntactically valid missing suffix may
                        // remain. RunCore still pins/checks the existing installation parent.
                        for (; index < parts.Length; index++) current = System.IO.Path.Combine(current, parts[index]);
                        return current;
                    }
                    throw PathFailure(error == 32 || error == 33 ? "FileBusy" : "AccessDenied", role, path, candidate, "", error);
                }
                pins.Add(handle);
                FileInfoNative info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw PathFailure("UnsafePath", role, path, candidate, "", Marshal.GetLastWin32Error());
                bool directory = (info.Attributes & DirectoryAttribute) != 0;
                if ((info.Attributes & ReparseAttribute) != 0 || (!directory && (index < parts.Length - 1 || info.Links != 1)))
                    throw PathFailure("UnsafePath", role, path, candidate, "", 0);
                StringBuilder final = new StringBuilder(32768);
                uint count = GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
                if (count == 0 || count >= final.Capacity || !final.ToString().StartsWith(@"\\?\", StringComparison.Ordinal))
                    throw PathFailure("UnsafePath", role, path, candidate, final.ToString(), Marshal.GetLastWin32Error());
                string resolved = final.ToString().Substring(4);
                string expectedParent = index < 0 ? current : current.TrimEnd('\\');
                string actualParent = index < 0 ? resolved : (System.IO.Path.GetDirectoryName(resolved) ?? "").TrimEnd('\\');
                if (!String.Equals(expectedParent, actualParent, StringComparison.OrdinalIgnoreCase))
                    throw PathFailure("UnsafePath", role, path, candidate, resolved, 0);
                current = resolved;
            }
            return current;
        } finally { for (int i = pins.Count - 1; i >= 0; i--) pins[i].Dispose(); }
    }
    static void PinAncestors(string directory, List<HeldFile> held, string[] trusted, bool checkAcl)
    {
        // Windows volume roots can allow creating unrelated directories. Hold them against renames and
        // reject redirection, but require the restrictive DACL only from the protected application parent.
        string parent = System.IO.Path.GetDirectoryName(directory);
        if (parent != null) PinAncestors(parent.TrimEnd('\\') + (parent.Length == 3 ? "\\" : ""), held, trusted, false);
        if (directory.Length == 2) directory += "\\";
        held.Add(new HeldFile(directory, "<ancestor>", true, false, false, trusted, checkAcl));
    }
    static Dictionary<string, string> LoadManifest(string path, string expectedHash, string[] inputTrust)
    {
        if (!IsHash(expectedHash)) throw new MaintenanceException("InvalidManifest", "");
        path = FullLocal(path, "<incoming-manifest-path>"); List<HeldFile> parents = new List<HeldFile>();
        try {
        PinAncestors(System.IO.Path.GetDirectoryName(path), parents, inputTrust, false);
        using (HeldFile input = new HeldFile(path, "<incoming-manifest>", false, false, false, inputTrust)) {
            if (input.Length <= 0 || input.Length > 4 * 1024 * 1024 || !String.Equals(input.Hash(), expectedHash, StringComparison.OrdinalIgnoreCase))
                throw new MaintenanceException("InvalidManifest", "<incoming-manifest>");
            input.Stream.Position = 0; byte[] bytes = new byte[(int)input.Length]; int offset = 0;
            while (offset < bytes.Length) { int n = input.Stream.Read(bytes, offset, bytes.Length - offset); if (n == 0) throw new MaintenanceException("InvalidManifest", ""); offset += n; }
            string text;
            try { text = new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF'); }
            catch (DecoderFallbackException) { throw new MaintenanceException("InvalidManifest", ""); }
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in text.Split('\n')) {
                string line = raw.EndsWith("\r", StringComparison.Ordinal) ? raw.Substring(0, raw.Length - 1) : raw;
                if (line.Length == 0) continue;
                if (line.Length < 67 || line[64] != ' ' || line[65] != '*' || !IsHash(line.Substring(0, 64))) throw new MaintenanceException("InvalidManifest", "");
                string name = RelativeName(line.Substring(66));
                if (InstallerMetadata.Contains(name) || result.ContainsKey(name) || result.Count >= MaximumEntries) throw new MaintenanceException("InvalidManifest", name);
                result.Add(name, line.Substring(0, 64));
            }
            if (result.Count == 0) throw new MaintenanceException("InvalidManifest", "");
            return result;
        }
        } finally { for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose(); }
    }

    public static string[] Run(string mode, string incomingManifestPath, string expectedManifestSha256)
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
            if (!Environment.Is64BitProcess || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new MaintenanceException("AccessDenied", "<installer>");
            string parent = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            return RunCore(mode, System.IO.Path.Combine(parent, "SteamSentinel"), incomingManifestPath,
                expectedManifestSha256, Catalog, Trusted, null);
        }
    }

#if STEAMSENTINEL_INSTALLER_TESTS
    public static string[] RunForTest(string mode, string root, string incomingManifestPath, string expectedManifestSha256,
        LegacyEntry[] approvedCatalog, Action beforeRetireRecheck)
    {
        string full = FullLocal(root, "<test-root>"), temp = FullLocal(System.IO.Path.GetTempPath(), "<test-temp>").TrimEnd('\\') + "\\";
        if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) || full.Length <= temp.Length) throw new MaintenanceException("UnsafePath", "<test-root>");
        List<string> trust = new List<string>(Trusted); trust.Add(WindowsIdentity.GetCurrent().User.Value);
        return RunCore(mode, full, incomingManifestPath, expectedManifestSha256, approvedCatalog, trust.ToArray(), beforeRetireRecheck);
    }
    public static LegacyEntry[] GetCatalogForTest() { return (LegacyEntry[])Catalog.Clone(); }
#endif

    static string[] RunCore(string mode, string root, string manifestPath, string manifestHash,
        LegacyEntry[] catalog, string[] trusted, Action beforeRetireRecheck)
    {
        if (mode != "Preflight" && mode != "Retire" && mode != "Verify") throw new MaintenanceException("InvalidManifest", "<mode>");
        root = FullLocal(root, "<installation-path>");
        List<string> inputTrust = new List<string>(Trusted); inputTrust.Add(WindowsIdentity.GetCurrent().User.Value);
        Dictionary<string, string> manifest = LoadManifest(manifestPath, manifestHash, inputTrust.ToArray());
        Dictionary<string, LegacyEntry> legacy = new Dictionary<string, LegacyEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (LegacyEntry entry in catalog) {
            string relative = RelativeName(entry.RelativePath);
            if (entry.Bytes < 0 || !IsHash(entry.Sha256) || legacy.ContainsKey(relative)) throw new MaintenanceException("InvalidManifest", relative);
            legacy.Add(relative, entry);
        }
        string parent = System.IO.Path.GetDirectoryName(root);
        List<HeldFile> held = new List<HeldFile>(); List<HeldFile> retired = new List<HeldFile>(); List<string> log = new List<string>();
        try {
            PinAncestors(parent, held, trusted, false);
            held.Add(new HeldFile(parent, "<parent>", true, false, false, trusted));
            uint rootAttributes = GetFileAttributes(root);
            if (rootAttributes == 0xFFFFFFFF) {
                int rootError = Marshal.GetLastWin32Error();
                if (rootError != 2 && rootError != 3) throw new MaintenanceException("AccessDenied", "");
                if (mode != "Preflight") throw new MaintenanceException("InstallationMissing", "");
                return new[] { "Preflight: no existing application payload." };
            }
            if ((rootAttributes & ReparseAttribute) != 0 || (rootAttributes & DirectoryAttribute) == 0)
                throw new MaintenanceException("UnsafePath", "");
            Queue<string> pending = new Queue<string>(); pending.Enqueue(root);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase); long total = 0; int entries = 0;
            while (pending.Count != 0) {
                string directory = pending.Dequeue();
                HeldFile pinnedDirectory = new HeldFile(directory, directory == root ? "" : directory.Substring(root.Length + 1), true, false, false, trusted);
                held.Add(pinnedDirectory);
                foreach (string path in Directory.GetFileSystemEntries(directory)) {
                    if (++entries > MaximumEntries || !path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) throw new MaintenanceException("UnsafePath", "<inventory>");
                    string relative = RelativeName(path.Substring(root.Length + 1));
                    FileAttributes attributes = File.GetAttributes(path);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) throw new MaintenanceException("UnsafePath", relative);
                    if ((attributes & FileAttributes.Directory) != 0) { pending.Enqueue(path); continue; }
                    bool incoming = manifest.ContainsKey(relative), metadata = InstallerMetadata.Contains(relative);
                    bool obsolete = !incoming && !metadata && legacy.ContainsKey(relative);
                    if (!incoming && !metadata && (!obsolete || mode == "Verify")) throw new MaintenanceException("UnknownFile", relative);
                    bool installedManifest = String.Equals(relative, "SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase);
                    HeldFile file = new HeldFile(path, relative, false, metadata && !installedManifest, obsolete && mode == "Retire", trusted); held.Add(file);
                    total += file.Length;
                    if (file.Length > MaximumFileBytes || total > MaximumTreeBytes) throw new MaintenanceException("UnsafePath", relative);
                    seen.Add(relative);
                    if (obsolete) {
                        LegacyEntry expected = legacy[relative];
                        if (file.Length != expected.Bytes || !String.Equals(file.Hash(), expected.Sha256, StringComparison.OrdinalIgnoreCase))
                            throw new MaintenanceException("LegacyContentMismatch", relative);
                        retired.Add(file);
                    } else if (incoming && mode != "Preflight" && !String.Equals(file.Hash(), manifest[relative], StringComparison.OrdinalIgnoreCase))
                        throw new MaintenanceException("NewPayloadMismatch", relative);
                    if (installedManifest && mode != "Preflight" && !String.Equals(file.Hash(), manifestHash, StringComparison.OrdinalIgnoreCase))
                        throw new MaintenanceException("NewPayloadMismatch", relative);
                }
            }
            if (mode != "Preflight") {
                foreach (string path in manifest.Keys) if (!seen.Contains(path)) throw new MaintenanceException("NewPayloadMissing", path);
                if (!seen.Contains("SHA256SUMS.txt")) throw new MaintenanceException("NewPayloadMissing", "SHA256SUMS.txt");
            }
            if (mode == "Retire") {
                if (beforeRetireRecheck != null) beforeRetireRecheck();
                // Validate every target and parent again before the first deletion. Content-changing handles
                // and renames are denied while held; unexpected ACL changes are rejected here.
                foreach (HeldFile item in held) item.Recheck(trusted);
                foreach (HeldFile file in retired) {
                    LegacyEntry expected = legacy[file.Relative];
                    if (!String.Equals(file.Hash(), expected.Sha256, StringComparison.OrdinalIgnoreCase)) throw new MaintenanceException("FileChanged", file.Relative);
                }
                foreach (HeldFile file in retired) {
                    Disposition disposition = new Disposition { DeleteFile = true };
                    if (!SetFileInformationByHandle(file.Handle, 4, ref disposition, (uint)Marshal.SizeOf(typeof(Disposition))))
                        throw new MaintenanceException("DeleteFailed", file.Relative);
                    log.Add("Retired: " + file.Relative + " SHA256=" + legacy[file.Relative].Sha256);
                }
            }
            log.Add(mode + ": verified " + manifest.Count + " incoming payload paths; retirement entries=" + retired.Count + ".");
            return log.ToArray();
        } catch (MaintenanceException error) { error.Operations = log.ToArray(); throw; }
        finally { for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose(); }
    }
}
