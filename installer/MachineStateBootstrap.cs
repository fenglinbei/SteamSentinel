using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

public sealed class MachineStateNode
{
    public string RelativePath, FileId, Owner, Group, Sddl, DescriptorBase64;
    public uint VolumeSerial, Attributes;
    public bool Exists;
}
public sealed class MachineStateResult
{
    public string Schema = "SteamSentinel.MachineStateBootstrap/1", Mode, ReasonCode, RelativePath = "", Detail = "";
    public bool Succeeded, MigrationRequired, Pending;
    public int Win32Error;
    public string JournalId = "", SourceManifestSha256 = "", JournalSha256 = "";
    public bool JournalComplete;
    public List<string> ChangedDirectories = new List<string>(), CreatedDirectories = new List<string>(), Operations = new List<string>();
    public List<string> PreviouslyRestrictedDirectories = new List<string>();
    public List<MachineStateNode> Before = new List<MachineStateNode>(), After = new List<MachineStateNode>();
}
public sealed class MachineStateException : IOException
{
    public string Code, RelativePath;
    public MachineStateResult Result;
    public int Win32Error;
    public MachineStateException(string code, string path) : base(code + ": " + path) { Code = code; RelativePath = path; }
}

// This installer helper never opens an old state file or changes a data object's permissions.
// The production entry point exposes no alternate filesystem root, registry hive or source catalog.
public static class SteamSentinelMachineStateBootstrap
{
    static readonly string[] Names = { "", "Quarantine", "Results", "BrokerTemp" };
    static readonly string[] Trusted = { "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
    static readonly string[] LegacyManifests = {
        "F01438E71FA743058BA1E2FE5893A928A45E6831EF97E2E1DF11F0781A62D829",
        "1BF96111D376B4FFFF266A54417F2A3C406E7190CEBAD7B83BD19998DBC57C8B" };
    const string SourceTree = "89ca1eb20274fa6faed5f2a8f678c17c3c60914a";
    const string RegistryPath = @"Software\SteamSentinel\Installer\LegacyStateMigration";
    const int WriteMask = 2 | 4 | 16 | 256 | 65536 | 64 | 262144 | 524288 | 0x10000000 | 0x40000000;
    const uint OpenFlags = 0x02200000, MaxAllowed = 0x02000000, ReadControl = 0x20000, ReadAttributes = 0x80;
    const int MaximumDescriptor = 8192, MaximumJournal = 131072;
    sealed class Config
    {
        public string Parent, Install, Key, LocalGroup;
        public string[] Trust, Manifests;
        public bool Test = false;
        public Action<string> Hook = null;
        public string Root { get { return Path.Combine(Parent, "SteamSentinel"); } }
    }
    sealed class Journal
    {
        public string Root, Manifest, Id, Hash;
        public bool Complete;
        public List<MachineStateNode> Original = new List<MachineStateNode>();
        public List<MachineStateNode> Created = new List<MachineStateNode>();
    }
    [StructLayout(LayoutKind.Sequential)] struct NativeInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StreamData
    {
        public long Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string Name;
    }
    [StructLayout(LayoutKind.Sequential)] struct Modals2 { public IntPtr Name, Sid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out NativeInfo info);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int cls, IntPtr data, uint bytes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder text, uint length, uint flags);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint flags, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(SafeFileHandle handle, uint type, uint flags, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr sd, out uint length);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstStreamW(string path, int level, out StreamData data, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextStreamW(IntPtr handle, out StreamData data);
    [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern uint NetUserModalsGet(string server, uint level, out IntPtr data);
    [DllImport("netapi32.dll")] static extern uint NetApiBufferFree(IntPtr data);

    static MachineStateException Error(string code, string path) { return new MachineStateException(code, path); }
    static MachineStateException NativeError(string code, string path, int error) { return new MachineStateException(code, path) { Win32Error = error }; }
    static string Full(string path)
    {
        if (String.IsNullOrEmpty(path) || !Regex.IsMatch(path, @"^[A-Za-z]:\\") || path.IndexOf(':', 2) >= 0 || path.IndexOf('/') >= 0)
            throw Error("UnsafeStatePath", "");
        string value = Path.GetFullPath(path).TrimEnd('\\');
        if (!String.Equals(value, path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) throw Error("UnsafeStatePath", "");
        return value;
    }
    static string Group()
    {
        IntPtr data; uint rc = NetUserModalsGet(null, 2, out data);
        if (rc != 0) throw Error("StateIdentityUnavailable", "");
        try { Modals2 m = (Modals2)Marshal.PtrToStructure(data, typeof(Modals2)); return new SecurityIdentifier(m.Sid).Value + "-513"; }
        finally { NetApiBufferFree(data); }
    }
    static string Label(string name) { return name.Length == 0 ? "root" : name; }
    static string Target(string name) { return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + (name == "BrokerTemp" ? "" : "(A;OICI;0x1200a9;;;BU)"); }
    static RawSecurityDescriptor Sd(MachineStateNode n) { return new RawSecurityDescriptor(Convert.FromBase64String(n.DescriptorBase64), 0); }
    static bool TrustedAcl(MachineStateNode n, Config c)
    {
        RawSecurityDescriptor sd = Sd(n);
        if (sd.Owner == null || Array.IndexOf(c.Trust, sd.Owner.Value) < 0 || sd.DiscretionaryAcl == null) return false;
        foreach (GenericAce entry in sd.DiscretionaryAcl)
        {
            CommonAce ace = entry as CommonAce;
            if (ace == null || ace.IsCallback) return false;
            if ((ace.AceFlags & AceFlags.InheritOnly) == 0 && ace.AceQualifier == AceQualifier.AccessAllowed &&
                (ace.AccessMask & WriteMask) != 0 && Array.IndexOf(c.Trust, ace.SecurityIdentifier.Value) < 0) return false;
        }
        return true;
    }
    static List<string> AceKeys(RawAcl acl)
    {
        if (acl == null || acl.Count > 32) throw Error("LegacyStateUnsupportedAcl", "");
        List<string> keys = new List<string>();
        foreach (GenericAce item in acl)
        {
            CommonAce ace = item as CommonAce;
            if (ace == null || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed) throw Error("LegacyStateUnsupportedAcl", "");
            keys.Add(((int)ace.AceFlags).ToString() + ":" + ace.AccessMask.ToString("X8") + ":" + ace.SecurityIdentifier.Value);
        }
        keys.Sort(StringComparer.Ordinal); return keys;
    }
    static bool SameAces(RawAcl a, RawAcl b)
    {
        List<string> x = AceKeys(a), y = AceKeys(b);
        return x.Count == y.Count && String.Join("|", x.ToArray()) == String.Join("|", y.ToArray());
    }
    static bool LegacyAcl(MachineStateNode n, Config c)
    {
        RawSecurityDescriptor sd = Sd(n);
        if (n.Owner != "S-1-5-32-544" || (n.Group != c.LocalGroup && n.Group != "S-1-5-32-544")) return false;
        ControlFlags allowed = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclAutoInherited;
        if ((sd.ControlFlags & ~allowed) != 0 || (sd.ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) == 0) return false;
        string expected = "D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" +
            (n.RelativePath == "BrokerTemp" ? "" : "(A;OICI;0x1200a9;;;BU)") +
            "(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)";
        return SameAces(sd.DiscretionaryAcl, new RawSecurityDescriptor(expected).DiscretionaryAcl);
    }
    static bool IsTarget(MachineStateNode n)
    {
        RawSecurityDescriptor sd = Sd(n);
        return (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 && SameAces(sd.DiscretionaryAcl, new RawSecurityDescriptor(Target(n.RelativePath)).DiscretionaryAcl);
    }
    static bool IdentityEqual(MachineStateNode a, MachineStateNode b)
    { return a.Exists == b.Exists && (!a.Exists || (a.FileId == b.FileId && a.VolumeSerial == b.VolumeSerial && a.Attributes == b.Attributes)); }
    static bool SecurityEqual(MachineStateNode a, MachineStateNode b) { return a.DescriptorBase64 == b.DescriptorBase64; }

    sealed class Pin : IDisposable
    {
        public readonly SafeFileHandle Handle;
        public readonly string PathName, Relative;
        public readonly bool Directory;
        public MachineStateNode Initial;
        public Pin(string path, string relative, bool directory, bool mutable, Config c, bool checkAcl, bool metadata = false)
        {
            PathName = path; Relative = relative; Directory = directory;
            // MAXIMUM_ALLOWED prevents SetSecurityInfo from propagating inheritable ACEs to children.
            // No share-delete pins the name; no share-write on mutation handles rejects conflicting opens.
            uint access = mutable ? MaxAllowed : ReadControl | ReadAttributes | (directory ? 1U : metadata ? 0U : 0x80000000U);
            Handle = CreateFile(path, access, mutable || (!directory && !metadata) ? 1U : 3U, IntPtr.Zero, 3, OpenFlags, IntPtr.Zero);
            if (Handle.IsInvalid) { int rc = Marshal.GetLastWin32Error(); Handle.Dispose(); throw NativeError(rc == 32 || rc == 33 ? "LegacyStateBusy" : "StateAccessDenied", relative, rc); }
            try { Initial = Read(); if (checkAcl && !TrustedAcl(Initial, c)) throw Error("UnsafeStatePermissions", relative); }
            catch { Handle.Dispose(); throw; }
        }
        public MachineStateNode Read()
        {
            NativeInfo info;
            StringBuilder final = new StringBuilder(32768);
            uint n = GetFinalPathNameByHandle(Handle, final, (uint)final.Capacity, 0);
            if (!GetFileInformationByHandle(Handle, out info) || n == 0 || n >= final.Capacity ||
                !String.Equals(final.ToString(), @"\\?\" + PathName, StringComparison.OrdinalIgnoreCase) ||
                (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != Directory || (!Directory && info.Links != 1))
                throw Error("UnsafeStatePath", Relative);
            IntPtr owner, group, dacl, sacl, descriptor;
            uint rc = GetSecurityInfo(Handle, 1, 7, out owner, out group, out dacl, out sacl, out descriptor);
            if (rc != 0) throw NativeError("StateAccessDenied", Relative, (int)rc);
            try {
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length < 20 || length > MaximumDescriptor) throw Error("LegacyStateUnsupportedAcl", Relative);
                byte[] bytes = new byte[length]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                RawSecurityDescriptor sd = new RawSecurityDescriptor(bytes, 0);
                return new MachineStateNode { RelativePath = Relative, Exists = true, FileId = info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8"),
                    VolumeSerial = info.Volume, Attributes = info.Attributes, Owner = sd.Owner == null ? "" : sd.Owner.Value,
                    Group = sd.Group == null ? "" : sd.Group.Value, Sddl = sd.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access), DescriptorBase64 = Convert.ToBase64String(bytes) };
            } finally { LocalFree(descriptor); }
        }
        public List<string> Entries(int maximum)
        {
            if (!Directory) throw Error("UnsafeStatePath", Relative);
            List<string> result = new List<string>(); IntPtr buffer = Marshal.AllocHGlobal(65536);
            try {
                bool first = true;
                while (true) {
                    bool ok = GetFileInformationByHandleEx(Handle, first ? 11 : 10, buffer, 65536); first = false;
                    if (!ok) { int rc = Marshal.GetLastWin32Error(); if (rc == 18) break; throw NativeError("StateEnumerationFailed", Relative, rc); }
                    int offset = 0;
                    while (true) {
                        if (offset < 0 || offset > 65536 - 104) throw Error("StateEnumerationFailed", Relative);
                        IntPtr row = IntPtr.Add(buffer, offset); int next = Marshal.ReadInt32(row), length = Marshal.ReadInt32(row, 60);
                        if (length < 2 || (length & 1) != 0 || length > 510 || offset + 104 + length > 65536) throw Error("StateEnumerationFailed", Relative);
                        string name = Marshal.PtrToStringUni(IntPtr.Add(row, 104), length / 2);
                        if (name != "." && name != "..") {
                            if (name.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || name.Length == 0) throw Error("UnsafeStatePath", Relative);
                            result.Add(name); if (result.Count > maximum) throw Error("LegacyStateContainsData", Relative);
                        }
                        if (next == 0) break;
                        if (next < 104 + length || offset + next >= 65536) throw Error("StateEnumerationFailed", Relative); offset += next;
                    }
                }
            } finally { Marshal.FreeHGlobal(buffer); }
            result.Sort(StringComparer.Ordinal); return result;
        }
        public void CheckStreams()
        {
            StreamData data; IntPtr find = FindFirstStreamW(PathName, 0, out data, 0);
            if (find == new IntPtr(-1)) { if (Marshal.GetLastWin32Error() == 38) return; throw Error("StateEnumerationFailed", Relative); }
            try { do { if (data.Name != "::$DATA" || data.Size != 0) throw Error("LegacyStateContainsData", Relative); } while (FindNextStreamW(find, out data));
                if (Marshal.GetLastWin32Error() != 38) throw Error("StateEnumerationFailed", Relative);
            } finally { FindClose(find); }
        }
        public void SetDacl()
        {
            IntPtr sd; uint bytes;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(Target(Relative), 1, out sd, out bytes)) throw Error("StatePermissionsChangeFailed", Relative);
            try { bool present, def; IntPtr dacl;
                if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out def) || !present || dacl == IntPtr.Zero ||
                    SetSecurityInfo(Handle, 1, 0x80000004U, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) != 0) throw Error("StatePermissionsChangeFailed", Relative);
            } finally { LocalFree(sd); }
        }
        public byte[] Bytes(int maximum)
        {
            NativeInfo info; if (!GetFileInformationByHandle(Handle, out info) || info.SizeHigh != 0 || info.SizeLow > maximum) throw Error("LegacySourceMismatch", Relative);
            using (FileStream stream = new FileStream(Handle, FileAccess.Read, 65536, false)) {
                byte[] result = new byte[info.SizeLow]; int offset = 0;
                while (offset < result.Length) { int n = stream.Read(result, offset, result.Length - offset); if (n == 0) throw Error("LegacySourceMismatch", Relative); offset += n; }
                return result;
            }
        }
        public string Hash(int maximum)
        {
            NativeInfo info; if (!GetFileInformationByHandle(Handle, out info) || info.SizeHigh != 0 || info.SizeLow > maximum) throw Error("LegacySourceMismatch", Relative);
            using (FileStream stream = new FileStream(Handle, FileAccess.Read, 65536, false))
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
        }
        public void Dispose() { Handle.Dispose(); }
    }

    static void Ancestors(string path, Config c, List<Pin> pins)
    {
        string current = path; List<string> paths = new List<string>();
        while (!String.IsNullOrEmpty(current)) { paths.Add(current.Length == 2 ? current + "\\" : current); current = Path.GetDirectoryName(current); }
        paths.Reverse(); foreach (string item in paths) pins.Add(new Pin(item, "<ancestor>", true, false, c, false));
    }
    static string Hex(byte[] bytes) { using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", ""); }
    static string SafeRelative(string value)
    {
        if (String.IsNullOrEmpty(value) || value.Length > 240 || value[0] == '\\' || value.IndexOfAny(new[] { '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0) throw Error("LegacySourceMismatch", "");
        foreach (char ch in value) if (ch < 32) throw Error("LegacySourceMismatch", "");
        foreach (string part in value.Split('\\')) if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)) throw Error("LegacySourceMismatch", "");
        return value;
    }
    static string VerifySource(Config c)
    {
        if (!c.Test) using (RegistryKey h = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (RegistryKey key = h.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9C3982D3-D18D-4B4E-A516-E8653A383683}_is1")) {
            if (key == null || !String.Equals(Convert.ToString(key.GetValue("DisplayVersion")), "0.2.0", StringComparison.Ordinal) ||
                !String.Equals(Convert.ToString(key.GetValue("InstallLocation")).TrimEnd('\\'), c.Install, StringComparison.OrdinalIgnoreCase)) throw Error("LegacySourceMismatch", "<installation>");
        }
        List<Pin> dirs = new List<Pin>();
        try {
            Ancestors(Path.GetDirectoryName(c.Install), c, dirs);
            Pin root = new Pin(c.Install, "<installation>", true, false, c, true); dirs.Add(root);
            byte[] manifest; using (Pin p = new Pin(Path.Combine(c.Install, "SHA256SUMS.txt"), "<old-manifest>", false, false, c, true)) manifest = p.Bytes(4 * 1024 * 1024);
            string hash = Hex(manifest); if (Array.IndexOf(c.Manifests, hash) < 0) throw Error("LegacySourceMismatch", "<old-manifest>");
            Dictionary<string, string> expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string text = new UTF8Encoding(false, true).GetString(manifest).TrimStart('\uFEFF');
            foreach (string raw in text.Split('\n')) {
                string line = raw.TrimEnd('\r'); if (line.Length == 0) continue;
                if (line.Length < 67 || !Regex.IsMatch(line.Substring(0, 64), "^[A-Fa-f0-9]{64}$") || line.Substring(64, 2) != " *") throw Error("LegacySourceMismatch", "<old-manifest>");
                string name = SafeRelative(line.Substring(66)); if (expected.ContainsKey(name) || expected.Count >= 4096) throw Error("LegacySourceMismatch", "<old-manifest>"); expected.Add(name, line.Substring(0, 64).ToUpperInvariant());
            }
            if (!expected.ContainsKey("VERSION.txt") || expected.Count == 0) throw Error("LegacySourceMismatch", "<old-manifest>");
            HashSet<string> found = new HashSet<string>(StringComparer.OrdinalIgnoreCase); long total = 0;
            VerifySourceDirectory(root, "", c, expected, found, dirs, ref total);
            if (found.Count != expected.Count) throw Error("LegacySourceMismatch", "<installation>");
            byte[] version; using (Pin p = new Pin(Path.Combine(c.Install, "VERSION.txt"), "VERSION.txt", false, false, c, true)) version = p.Bytes(65536);
            string v = new UTF8Encoding(false, true).GetString(version).TrimStart('\uFEFF');
            if (!Regex.IsMatch(v, @"(?m)^Product=SteamSentinel\r?$") || !Regex.IsMatch(v, @"(?m)^Version=0\.2\.0\r?$") || !Regex.IsMatch(v, "(?m)^SourceTree=" + SourceTree + "\\r?$")) throw Error("LegacySourceMismatch", "VERSION.txt");
            // Payload file hashes are read under write-excluding handles. Their restrictive DACLs
            // prevent standard-user changes after close; this is not a transaction against administrators.
            foreach (Pin p in dirs) { MachineStateNode now = p.Read(); if (!IdentityEqual(p.Initial, now) || !SecurityEqual(p.Initial, now)) throw Error("LegacySourceChanged", p.Relative); }
            return hash;
        } finally { foreach (Pin p in dirs) p.Dispose(); }
    }
    static void VerifySourceDirectory(Pin directory, string relative, Config c, Dictionary<string, string> expected, HashSet<string> found, List<Pin> held, ref long total)
    {
        if (held.Count > 1024) throw Error("LegacySourceMismatch", relative);
        foreach (string name in directory.Entries(4096)) {
            string rel = relative.Length == 0 ? name : relative + "\\" + name; SafeRelative(rel);
            string path = Path.Combine(directory.PathName, name);
            FileAttributes attr = File.GetAttributes(path);
            if ((attr & FileAttributes.ReparsePoint) != 0) throw Error("UnsafeStatePath", "<installation>");
            if ((attr & FileAttributes.Directory) != 0) {
                Pin child = new Pin(path, rel, true, false, c, true); held.Add(child); VerifySourceDirectory(child, rel, c, expected, found, held, ref total);
            } else {
                bool metadata = relative.Length == 0 && (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(name, @"^unins000\.(exe|dat|msg)$", RegexOptions.IgnoreCase));
                string digest; if (!expected.TryGetValue(rel, out digest) && !metadata) throw Error("LegacySourceMismatch", rel);
                if (digest != null) using (Pin p = new Pin(path, rel, false, false, c, true)) {
                    NativeInfo info; if (!GetFileInformationByHandle(p.Handle, out info)) throw Error("LegacySourceMismatch", rel); total += ((long)info.SizeHigh << 32) | info.SizeLow;
                    if (total > 2L * 1024 * 1024 * 1024 || p.Hash(512 * 1024 * 1024) != digest) throw Error("LegacySourceMismatch", rel); found.Add(rel);
                }
                else using (Pin p = new Pin(path, rel, false, false, c, true, true)) { }
            }
        }
    }

    static void CheckRegistrySecurity(RegistryKey key, Config c)
    {
        RegistrySecurity acl = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        RawSecurityDescriptor sd = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
        string current = WindowsIdentity.GetCurrent().User.Value;
        if (sd.Owner == null || (Array.IndexOf(c.Trust, sd.Owner.Value) < 0 && !(c.Test && sd.Owner.Value == current)) || sd.DiscretionaryAcl == null) throw Error("MigrationJournalUnsafe", "<installer-state>");
        foreach (GenericAce e in sd.DiscretionaryAcl) {
            CommonAce a = e as CommonAce; if (a == null || a.IsCallback) throw Error("MigrationJournalUnsafe", "<installer-state>");
            if ((a.AceFlags & AceFlags.InheritOnly) == 0 && a.AceQualifier == AceQualifier.AccessAllowed &&
                (a.AccessMask & (2 | 4 | 0x20 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000)) != 0 &&
                Array.IndexOf(c.Trust, a.SecurityIdentifier.Value) < 0 && !(c.Test && a.SecurityIdentifier.Value == current)) throw Error("MigrationJournalUnsafe", "<installer-state>");
        }
    }
    static RegistryKey OpenJournal(Config c, bool create)
    {
        RegistryKey key = RegistryKey.OpenBaseKey(c.Test ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, RegistryView.Registry64);
        try {
            string[] parts = c.Key.Split('\\');
            for (int i = 0; i < parts.Length; i++) {
                RegistryKey next = key.OpenSubKey(parts[i], create);
                if (next == null && create) {
                    RegistrySecurity security = new RegistrySecurity();
                    security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)" + (c.Test ? "(A;CI;KA;;;" + WindowsIdentity.GetCurrent().User.Value + ")" : ""));
                    next = key.CreateSubKey(parts[i], RegistryKeyPermissionCheck.ReadWriteSubTree, security);
                }
                if (next == null) { key.Dispose(); return null; }
                key.Dispose(); key = next;
                // Software is an OS-managed parent. Every product-specific ancestor is checked.
                if (i > 0) CheckRegistrySecurity(key, c);
            }
            if (key.GetSubKeyNames().Length != 0 || key.GetValueNames().Length > 1 || (key.GetValueNames().Length == 1 && key.GetValueNames()[0] != "Journal")) throw Error("MigrationJournalUnsafe", "<installer-state>");
            return key;
        } catch { key.Dispose(); throw; }
    }
    static void NodeWrite(BinaryWriter w, MachineStateNode n)
    {
        w.Write(n.RelativePath); w.Write(n.Exists); if (!n.Exists) return;
        w.Write(n.FileId); w.Write(n.VolumeSerial); w.Write(n.Attributes); w.Write(n.Owner); w.Write(n.Group); w.Write(n.DescriptorBase64);
    }
    static MachineStateNode NodeRead(BinaryReader r)
    {
        MachineStateNode n = new MachineStateNode { RelativePath = r.ReadString(), Exists = r.ReadBoolean() };
        if (Array.IndexOf(Names, n.RelativePath) < 0) throw Error("MigrationJournalUnsafe", "<installer-state>");
        if (n.Exists) { n.FileId = r.ReadString(); n.VolumeSerial = r.ReadUInt32(); n.Attributes = r.ReadUInt32(); n.Owner = r.ReadString(); n.Group = r.ReadString(); n.DescriptorBase64 = r.ReadString();
            if (!Regex.IsMatch(n.FileId, "^[A-F0-9]{16}$") || n.DescriptorBase64.Length > MaximumDescriptor * 2) throw Error("MigrationJournalUnsafe", "<installer-state>");
            RawSecurityDescriptor sd = Sd(n); if (sd.Owner == null || sd.Group == null || sd.Owner.Value != n.Owner || sd.Group.Value != n.Group) throw Error("MigrationJournalUnsafe", "<installer-state>"); n.Sddl = sd.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access); }
        return n;
    }
    static Journal LoadJournal(Config c)
    {
        using (RegistryKey key = OpenJournal(c, false)) {
            if (key == null || key.GetValueNames().Length == 0) return null;
            byte[] bytes = key.GetValue("Journal", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
            if (bytes == null || bytes.Length > MaximumJournal) throw Error("MigrationJournalUnsafe", "<installer-state>");
            using (BinaryReader r = new BinaryReader(new MemoryStream(bytes), new UTF8Encoding(false, true))) {
                if (r.ReadString() != "SteamSentinel.LegacyEmptyState/1") throw Error("MigrationJournalUnsafe", "<installer-state>");
                Journal j = new Journal { Root = r.ReadString(), Manifest = r.ReadString(), Id = r.ReadString(), Complete = r.ReadBoolean(), Hash = Hex(bytes) };
                if (j.Root != c.Root || Array.IndexOf(c.Manifests, j.Manifest) < 0 || !Regex.IsMatch(j.Id, "^[a-f0-9]{32}$") || r.ReadInt32() != 4) throw Error("MigrationJournalUnsafe", "<installer-state>");
                for (int i = 0; i < 4; i++) { MachineStateNode n = NodeRead(r); if (n.RelativePath != Names[i]) throw Error("MigrationJournalUnsafe", "<installer-state>");
                    if (n.Exists && !TrustedAcl(n, c) && !LegacyAcl(n, c)) throw Error("MigrationJournalUnsafe", "<installer-state>"); j.Original.Add(n); }
                int count = r.ReadInt32(); if (count < 0 || count > 4) throw Error("MigrationJournalUnsafe", "<installer-state>");
                HashSet<string> names = new HashSet<string>(); for (int i = 0; i < count; i++) { MachineStateNode n = NodeRead(r);
                    if (!n.Exists || !names.Add(n.RelativePath) || j.Original[Array.IndexOf(Names, n.RelativePath)].Exists ||
                        n.Owner != "S-1-5-32-544" || n.Group != "S-1-5-32-544" || !IsTarget(n) || !TrustedAcl(n, c)) throw Error("MigrationJournalUnsafe", "<installer-state>"); j.Created.Add(n); }
                if (r.BaseStream.Position != r.BaseStream.Length) throw Error("MigrationJournalUnsafe", "<installer-state>"); return j;
            }
        }
    }
    static void SaveJournal(Config c, Journal j)
    {
        byte[] bytes; using (MemoryStream memory = new MemoryStream()) {
            using (BinaryWriter w = new BinaryWriter(memory, new UTF8Encoding(false, true), true)) {
                w.Write("SteamSentinel.LegacyEmptyState/1"); w.Write(j.Root); w.Write(j.Manifest); w.Write(j.Id); w.Write(j.Complete); w.Write(4);
                foreach (MachineStateNode n in j.Original) NodeWrite(w, n); w.Write(j.Created.Count); foreach (MachineStateNode n in j.Created) NodeWrite(w, n); w.Flush();
            } bytes = memory.ToArray();
        }
        if (bytes.Length > MaximumJournal) throw Error("MigrationJournalUnsafe", "<installer-state>");
        using (RegistryKey key = OpenJournal(c, true)) { key.SetValue("Journal", bytes, RegistryValueKind.Binary); key.Flush();
            byte[] read = key.GetValue("Journal") as byte[]; if (read == null || Convert.ToBase64String(read) != Convert.ToBase64String(bytes)) throw Error("MigrationJournalWriteFailed", "<installer-state>"); j.Hash = Hex(bytes); }
    }
    static void JournalResult(MachineStateResult result, Journal journal)
    {
        if (journal == null) return;
        result.JournalId = journal.Id; result.SourceManifestSha256 = journal.Manifest;
        result.JournalSha256 = journal.Hash; result.JournalComplete = journal.Complete; result.Pending = !journal.Complete;
    }
    static MachineStateNode Missing(string name) { return new MachineStateNode { RelativePath = name, Exists = false }; }
    static void EmptyTree(Dictionary<string, Pin> pins)
    {
        Pin root; if (!pins.TryGetValue("", out root)) { if (pins.Count != 0) throw Error("LegacyStateChanged", ""); return; }
        List<string> children = root.Entries(3);
        HashSet<string> expected = new HashSet<string>(StringComparer.Ordinal); foreach (string name in pins.Keys) if (name.Length != 0) expected.Add(name);
        foreach (string name in children) if (!expected.Contains(name)) throw Error("LegacyStateContainsData", name);
        if (children.Count != expected.Count) throw Error("LegacyStateChanged", "");
        foreach (Pin p in pins.Values) { if (p.Relative.Length != 0 && p.Entries(0).Count != 0) throw Error("LegacyStateContainsData", p.Relative); p.CheckStreams(); }
    }
    static void Recheck(Dictionary<string, Pin> pins, Dictionary<string, MachineStateNode> expected)
    {
        foreach (KeyValuePair<string, Pin> pair in pins) { MachineStateNode actual = pair.Value.Read(), earlier = expected[pair.Key];
            if (!IdentityEqual(earlier, actual) || !SecurityEqual(earlier, actual)) throw Error("LegacyStateChanged", pair.Key); }
        EmptyTree(pins);
    }
    static void Hook(Config c, string stage) { if (c.Hook != null) c.Hook(stage); }
    static Pin CreateDirectory(string name, Config c, List<Pin> held)
    {
        string path = name.Length == 0 ? c.Root : Path.Combine(c.Root, name);
        if (Directory.Exists(path) || File.Exists(path)) throw Error("LegacyStateChanged", name);
        DirectorySecurity acl = new DirectorySecurity(); acl.SetSecurityDescriptorSddlForm("O:BAG:BA" + Target(name));
        // Native CreateDirectory fails if anything already occupies this exact name.
        byte[] sd = acl.GetSecurityDescriptorBinaryForm(); GCHandle memory = GCHandle.Alloc(sd, GCHandleType.Pinned);
        try { SecurityAttributes sa = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor = memory.AddrOfPinnedObject() };
            if (!CreateDirectoryW(path, ref sa)) throw Error(Marshal.GetLastWin32Error() == 183 ? "LegacyStateChanged" : "StateCreateFailed", name);
        } finally { memory.Free(); }
        Pin result = new Pin(path, name, true, true, c, true); held.Add(result); if (!IsTarget(result.Initial)) throw Error("StatePermissionsChangeFailed", name); return result;
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateDirectoryW(string path, ref SecurityAttributes security);

    static MachineStateResult Execute(string mode, Config c)
    {
        MachineStateResult result = new MachineStateResult { Mode = mode, ReasonCode = "StateOperationFailed" };
        List<Pin> held = new List<Pin>(); Dictionary<string, Pin> pins = new Dictionary<string, Pin>(StringComparer.Ordinal);
        try {
            if (mode != "Inspect" && mode != "Prepare" && mode != "Verify") throw Error("InvalidStateMode", "");
            using (WindowsIdentity id = WindowsIdentity.GetCurrent()) if (!new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)) throw Error("StateAdministratorRequired", "");
            c.Parent = Full(c.Parent); c.Install = Full(c.Install); c.LocalGroup = Group(); Ancestors(c.Parent, c, held);
            Journal journal = LoadJournal(c); result.Pending = journal != null && !journal.Complete; JournalResult(result, journal);
            bool unsafeAcl = false, missing = false;
            foreach (string name in Names) {
                string path = name.Length == 0 ? c.Root : Path.Combine(c.Root, name);
                // File.GetAttributes distinguishes missing paths from denied paths. Exists alone does not.
                FileAttributes attr;
                try { attr = File.GetAttributes(path); }
                catch (FileNotFoundException) { result.Before.Add(Missing(name)); missing = true; continue; }
                catch (DirectoryNotFoundException) { result.Before.Add(Missing(name)); missing = true; continue; }
                if ((attr & FileAttributes.Directory) == 0 || (attr & FileAttributes.ReparsePoint) != 0) throw Error("UnsafeStatePath", name);
                Pin pin = new Pin(path, name, true, mode == "Prepare", c, false); held.Add(pin); pins.Add(name, pin); result.Before.Add(pin.Initial);
                if (!TrustedAcl(pin.Initial, c)) { if (!LegacyAcl(pin.Initial, c)) throw Error("LegacyStateUnsupportedAcl", name); unsafeAcl = true; }
            }
            result.MigrationRequired = unsafeAcl || result.Pending;
            if (mode == "Verify" && (missing || unsafeAcl || result.Pending)) throw Error(result.Pending ? "LegacyStateMigrationPending" : missing ? "StateDirectoryMissing" : "UnsafeStatePermissions", "");
            if (!unsafeAcl && !result.Pending) {
                if (mode == "Prepare" && missing) foreach (string name in Names) if (!pins.ContainsKey(name)) {
                    Pin made = CreateDirectory(name, c, held); pins.Add(name, made); result.CreatedDirectories.Add(name); result.Operations.Add("Created:" + Label(name));
                }
                result.ReasonCode = missing && mode == "Inspect" ? "StateDirectoriesWillBeCreated" : result.CreatedDirectories.Count > 0 ? "StateDirectoriesCreated" : "StateReady";
            } else {
                EmptyTree(pins); string proof = VerifySource(c); Hook(c, "after-source");
                Dictionary<string, MachineStateNode> expected = new Dictionary<string, MachineStateNode>(StringComparer.Ordinal);
                foreach (KeyValuePair<string, Pin> p in pins) {
                    MachineStateNode now = p.Value.Read();
                    if (!IdentityEqual(p.Value.Initial, now) || !SecurityEqual(p.Value.Initial, now)) throw Error("LegacyStateChanged", p.Key);
                    expected.Add(p.Key, now);
                }
                // Inspect makes no changes, but must not advertise a migratable empty tree
                // after a concurrent item appeared while the old payload was being hashed.
                Recheck(pins, expected);
                if (result.Pending) {
                    if (journal.Manifest != proof) throw Error("LegacySourceMismatch", "<pending-source>");
                    foreach (MachineStateNode old in journal.Original) {
                        Pin p; bool exists = pins.TryGetValue(old.RelativePath, out p);
                        if (old.Exists) {
                            if (!exists || !IdentityEqual(old, p.Read())) throw Error("LegacyStateChanged", old.RelativePath);
                            MachineStateNode current = p.Read();
                            if (!SecurityEqual(old, current)) {
                                // Safe original nodes must retain their exact descriptor. Only a recorded
                                // legacy node can move to the deterministic restricted target descriptor.
                                if (TrustedAcl(old, c) || !LegacyAcl(old, c) || current.Owner != old.Owner || current.Group != old.Group || !IsTarget(current)) throw Error("LegacyStateChanged", old.RelativePath);
                                result.PreviouslyRestrictedDirectories.Add(old.RelativePath);
                            }
                        } else {
                            MachineStateNode saved = journal.Created.Find(delegate(MachineStateNode n) { return n.RelativePath == old.RelativePath; });
                            if (saved != null) {
                                if (!exists || !IdentityEqual(saved, p.Read()) || !SecurityEqual(saved, p.Read())) throw Error("LegacyStateChanged", old.RelativePath);
                            } else if (exists) throw Error("LegacyStateChanged", old.RelativePath);
                        }
                    }
                }
                if (mode == "Inspect") result.ReasonCode = result.Pending ? "LegacyStateMigrationPending" : "LegacyStateMigrationRequired";
                else {
                    if (!result.Pending) {
                        journal = new Journal { Root = c.Root, Manifest = proof, Id = Guid.NewGuid().ToString("N"), Complete = false };
                        journal.Original.AddRange(result.Before); Hook(c, "before-pending"); Recheck(pins, expected); SaveJournal(c, journal); result.Pending = true;
                    }
                    foreach (string name in Names) {
                        Hook(c, "before-change:" + Label(name)); Recheck(pins, expected);
                        Pin pin;
                        if (!pins.TryGetValue(name, out pin)) {
                            pin = CreateDirectory(name, c, held); pins.Add(name, pin); expected.Add(name, pin.Read()); journal.Created.Add(pin.Read());
                            result.CreatedDirectories.Add(name); result.Operations.Add("Created:" + Label(name)); SaveJournal(c, journal);
                        } else if (!TrustedAcl(pin.Read(), c)) {
                            MachineStateNode prior = pin.Read(); if (!LegacyAcl(prior, c)) throw Error("LegacyStateUnsupportedAcl", name);
                            pin.SetDacl(); result.ChangedDirectories.Add(name); result.Operations.Add("Restricted:" + Label(name));
                            MachineStateNode after = pin.Read();
                            if (!IdentityEqual(prior, after) || prior.Owner != after.Owner || prior.Group != after.Group || !IsTarget(after)) throw Error("StatePermissionsChangeFailed", name);
                            expected[name] = after; SaveJournal(c, journal);
                        }
                        Recheck(pins, expected); Hook(c, "after-change:" + Label(name));
                    }
                    Hook(c, "before-complete"); Recheck(pins, expected);
                    foreach (Pin p in pins.Values) if (!TrustedAcl(p.Read(), c)) throw Error("UnsafeStatePermissions", p.Relative);
                    journal.Complete = true; SaveJournal(c, journal); result.Pending = false; result.ReasonCode = "LegacyStateMigrated";
                }
            }
            JournalResult(result, journal);
            foreach (Pin p in pins.Values) result.After.Add(p.Read());
            result.Succeeded = true; return result;
        } catch (Exception ex) {
            MachineStateException error = ex as MachineStateException ?? Error("StateOperationFailed", "");
            result.Succeeded = false; result.ReasonCode = error.Code; result.RelativePath = error.RelativePath; result.Win32Error = error.Win32Error;
            result.Detail = ex.GetType().Name + (ex is Win32Exception ? ":" + ((Win32Exception)ex).NativeErrorCode.ToString() : "");
            result.After.Clear(); foreach (Pin p in pins.Values) try { result.After.Add(p.Read()); } catch { }
            try { Journal current = LoadJournal(c); result.Pending = current != null && !current.Complete; JournalResult(result, current); } catch { result.Pending = true; }
            error.Result = result; throw error;
        } finally { for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose(); }
    }
    public static MachineStateResult Run(string mode)
    {
        return Execute(mode, new Config { Parent = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Install = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SteamSentinel"), Key = RegistryPath, Trust = Trusted, Manifests = LegacyManifests });
    }
#if STEAMSENTINEL_INSTALLER_TESTS
    public static MachineStateResult RunForTests(string mode, string stateParent, string installRoot, string registrySubKey,
        string[] trustedOwnerSids, string[] approvedManifestSha256, Action<string> faultHook)
    {
        if (!Regex.IsMatch(registrySubKey, @"^Software\\SteamSentinelMachineStateTests\\[a-fA-F0-9-]{36}$")) throw new ArgumentException("Dedicated HKCU test GUID key required.");
        return Execute(mode, new Config { Parent = stateParent, Install = installRoot, Key = registrySubKey,
            Trust = trustedOwnerSids, Manifests = approvedManifestSha256, Hook = faultHook, Test = true });
    }
#endif
}
