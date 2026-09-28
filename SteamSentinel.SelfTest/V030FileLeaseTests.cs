using System.ComponentModel;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using SteamSentinel.Broker;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestReadOnlyFileLeaseAsync(string root)
    {
        foreach (FileAttributes attributes in new[] { FileAttributes.ReadOnly, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System })
        {
            string source = Path.Combine(root, $"readonly-{(int)attributes}.bin");
            string destination = source + ".quarantined";
            await File.WriteAllTextAsync(source, "Inert readonly quarantine regression fixture.");
            string hash = await Hashing.Sha256FileAsync(source);
            File.SetAttributes(source, attributes);
            string? error = null;
            try
            {
                await using SecureFileLease lease = SecureFileLease.Open(source);
                await lease.CopyToAsync(destination, hash, CancellationToken.None);
                lease.DeleteOnClose();
            }
            catch (Win32Exception ex) { error = $"Win32={ex.NativeErrorCode}: {ex.Message}"; }
            try
            {
                Check($"只读文件句柄隔离 {(int)attributes} 删除与副本哈希" + (error is null ? "" : $" ({error})"),
                    error is null && !File.Exists(source) && await Hashing.Sha256FileAsync(destination) == hash);
            }
            finally { if (File.Exists(source)) File.SetAttributes(source, FileAttributes.Normal); }
        }

        string retained = Path.Combine(root, "readonly-failed-copy.bin");
        await File.WriteAllTextAsync(retained, "Inert fixture retained after a bad backup hash.");
        string retainedHash = await Hashing.Sha256FileAsync(retained);
        File.SetAttributes(retained, FileAttributes.ReadOnly);
        bool rejected = false;
        try
        {
            await using SecureFileLease lease = SecureFileLease.Open(retained);
            try { await lease.CopyToAsync(retained + ".quarantined", new string('0', 64), CancellationToken.None); }
            catch (IOException) { rejected = true; }
            Check("隔离副本复核失败保留只读原文件与属性", rejected &&
                await lease.ComputeSha256Async(CancellationToken.None) == retainedHash &&
                File.GetAttributes(retained).HasFlag(FileAttributes.ReadOnly));
        }
        finally { File.SetAttributes(retained, FileAttributes.Normal); }

        foreach (bool readOnly in new[] { false, true })
        {
            string source = Path.Combine(root, $"deny-write-attributes-{readOnly}.bin");
            await File.WriteAllTextAsync(source, "Inert ACL boundary fixture.");
            string hash = await Hashing.Sha256FileAsync(source);
            if (readOnly) File.SetAttributes(source, FileAttributes.ReadOnly);
            FileInfo file = new(source);
            FileSecurity denied = file.GetAccessControl();
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            FileSystemAccessRule denyWrite = new(identity.User!, FileSystemRights.WriteAttributes, AccessControlType.Deny);
            denied.AddAccessRule(denyWrite);
            file.SetAccessControl(denied);
            bool removed = false;
            try
            {
                try
                {
                    await using SecureFileLease lease = SecureFileLease.Open(source);
                    await lease.CopyToAsync(source + ".quarantined", hash, CancellationToken.None);
                    lease.DeleteOnClose();
                    removed = true;
                }
                catch (Win32Exception) { }
                Check(readOnly ? "只读隔离遵守元数据写入拒绝 ACL" : "普通文件不强制要求元数据写权限",
                    readOnly ? !removed && File.Exists(source) && File.GetAttributes(source).HasFlag(FileAttributes.ReadOnly)
                             : removed && !File.Exists(source));
            }
            finally
            {
                if (File.Exists(source))
                {
                    FileSecurity restore = file.GetAccessControl();
                    restore.RemoveAccessRuleSpecific(denyWrite);
                    file.SetAccessControl(restore);
                    File.SetAttributes(source, FileAttributes.Normal);
                }
            }
        }
    }
}
