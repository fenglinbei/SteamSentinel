using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Windows.Controls;
using SteamSentinel.App;
using SteamSentinel.App.Services;
using SteamSentinel.App.ViewModels;
using SteamSentinel.Broker;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV017Async(string root)
    {
        foreach (FileSystemRights rights in new[]
        {
            FileSystemRights.Read, FileSystemRights.ReadAndExecute, FileSystemRights.ReadPermissions,
            FileSystemRights.Synchronize, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            (FileSystemRights)unchecked((int)0xA0000000)
        }) Check($"读取权限不误判为写入：{rights}", !InstallationSecurity.GrantsWrite(rights));

        foreach (FileSystemRights rights in new[]
        {
            FileSystemRights.WriteData, FileSystemRights.AppendData, FileSystemRights.WriteExtendedAttributes,
            FileSystemRights.WriteAttributes, FileSystemRights.Delete, FileSystemRights.DeleteSubdirectoriesAndFiles,
            FileSystemRights.ChangePermissions, FileSystemRights.TakeOwnership,
            FileSystemRights.Write, FileSystemRights.Modify, FileSystemRights.FullControl,
            (FileSystemRights)0x10000000, (FileSystemRights)0x40000000
        }) Check($"真实写权限仍被拦截：{rights}", InstallationSecurity.GrantsWrite(rights));

        const string trusted = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
        (string Name, string Sddl, bool Allowed)[] acls =
        [
            ("默认用户 RX 加同步权限", trusted + "(A;;0x1200a9;;;BU)", true),
            ("通用读与执行权限", trusted + "(A;;GRGX;;;BU)", true),
            ("仅继承的创建者权限不应用于当前目录", trusted + "(A;OICIIO;GA;;;CO)", true),
            ("用户继承写入规则在子对象处检查", trusted + "(A;OICIIO;GW;;;BU)", true),
            ("子对象的继承写入不能跳过", trusted + "(A;ID;GW;;;BU)", false),
            ("普通用户通用全部权限", trusted + "(A;;GA;;;BU)", false),
            ("交互用户写入", trusted + "(A;;GW;;;IU)", false),
            ("已验证用户写入", trusted + "(A;;FW;;;AU)", false),
            ("所有用户写入", trusted + "(A;;FW;;;WD)", false),
            ("任意直接账户写入", trusted + "(A;;FW;;;S-1-5-21-1-2-3-1001)", false),
            ("任意自定义组写入", trusted + "(A;;FW;;;S-1-5-21-1-2-3-2001)", false),
            ("非受信任所有者", "O:S-1-5-21-1-2-3-1001G:BAD:P(A;;FA;;;BA)", false),
            ("空 DACL 拒绝访问不是任意写入", "O:BAG:BAD:P", true),
            ("NULL DACL 任意访问不通过", "O:BAG:BAD:NO_ACCESS_CONTROL", false)
        ];
        foreach ((string name, string sddl, bool allowed) in acls)
        {
            DirectorySecurity acl = new(); acl.SetSecurityDescriptorSddlForm(sddl);
            byte[] before = acl.GetSecurityDescriptorBinaryForm();
            InstallationSecurityStatus status = InstallationSecurity.CheckSecurityDescriptor(acl, "fixture");
            Check("安装 ACL：" + name, status.IsProtected == allowed && before.SequenceEqual(acl.GetSecurityDescriptorBinaryForm()));
        }

        string sums = Path.Combine(root, "v017-SHA256SUMS.txt"), hash = new('A', 64);
        await File.WriteAllTextAsync(sums, $"{hash} *SteamSentinel.dll\n{hash} *zh-Hans/fixture.resources.dll\n");
        Dictionary<string, string> parsed = InstallationSecurity.ReadChecksums(sums);
        Check("完整性清单保留托管组件与语言子目录", parsed.Count == 2 && parsed.ContainsKey("zh-Hans\\fixture.resources.dll"));
        foreach (string badPath in new[] { "..\\escape.dll", "C:\\escape.dll", "\\escape.dll", "a:stream", "dir\\.\\x.dll", "x.dll.", "dir\\\\x.dll" })
        {
            await File.WriteAllTextAsync(sums, $"{hash} *{badPath}\n");
            bool rejected = false;
            try { InstallationSecurity.ReadChecksums(sums); } catch (InvalidDataException) { rejected = true; }
            Check("拒绝不安全清单路径：" + badPath, rejected);
        }
        await File.WriteAllTextAsync(sums, $"{hash} *app.dll\n{hash} *APP.DLL\n");
        bool duplicateRejected = false;
        try { InstallationSecurity.ReadChecksums(sums); } catch (InvalidDataException) { duplicateRejected = true; }
        Check("清单大小写重复不能覆盖旧校验值", duplicateRejected);

        int starts = 0, validations = 0;
        ElevationService success = new(() => { validations++; return InstallationSecurityStatus.Protected; }, info =>
        {
            starts++;
            Check("提权只启动固定应用且不传递路径或处置计划", info.FileName == Path.Combine(AppContext.BaseDirectory, "SteamSentinel.exe") &&
                info.WorkingDirectory == AppContext.BaseDirectory && info.Verb == "runas" && info.UseShellExecute &&
                info.WindowStyle == ProcessWindowStyle.Normal && info.ArgumentList.SequenceEqual([ElevationService.WindowArgument]));
            return true;
        });
        Check("提权启动前重新检查安装", success.OpenAdministratorWindow() == ElevationOutcome.Opened && starts == 1 && validations == 1);
        ElevationService cancelled = new(() => InstallationSecurityStatus.Protected, _ => throw new Win32Exception(1223));
        Check("取消 UAC 返回取消状态而非异常", cancelled.OpenAdministratorWindow() == ElevationOutcome.Cancelled);
        bool blocked = false;
        try { new ElevationService(() => new(false, "unsafe fixture"), _ => { starts++; return true; }).OpenAdministratorWindow(); }
        catch (UnauthorizedAccessException) { blocked = true; }
        Check("不安全安装不能通过提权按钮绕过", blocked && starts == 1);
        bool startFailure = false;
        try { new ElevationService(() => InstallationSecurityStatus.Protected, _ => false).OpenAdministratorWindow(); }
        catch (InvalidOperationException) { startFailure = true; }
        Check("未产生新进程不报告启动成功", startFailure);
        bool denied = false;
        try { new ElevationService(() => InstallationSecurityStatus.Protected, _ => throw new Win32Exception(5)).OpenAdministratorWindow(); }
        catch (Win32Exception) { denied = true; }
        Check("系统拒绝授权不伪装为用户取消", denied);

        RemediationPlan otherAccount = new() { RequestedBySid = "S-1-5-21-1-2-3-1001" };
        Directory.CreateDirectory(AppPaths.PlansRoot);
        string planPath = Path.Combine(AppPaths.PlansRoot, $"plan-{otherAccount.PlanId:N}.json");
        try
        {
            await JsonFile.WriteAtomicAsync(planPath, otherAccount);
            bool otherSidRejected = false;
            try { await BrokerRequestReader.ReadAsync(planPath, await Hashing.Sha256FileExclusiveAsync(planPath)); }
            catch (UnauthorizedAccessException) { otherSidRejected = true; }
            Check("提权入口不放宽 Broker 请求者 SID 绑定", otherSidRejected);
        }
        finally { File.Delete(planPath); }
    }

    // Called on the existing WPF test thread, without opening windows or invoking UAC.
    private static void TestV017Window()
    {
        MainWindow window = new();
        ScanReport report = new();
        report.Findings.Add(new Finding { CanRemediate = true, IsKnownMalware = true, Title = "inert fixture" });
        window.Findings.Add(new FindingItemViewModel(report.Findings[0]));
        typeof(MainWindow).GetField("_lastReport", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, report);
        Button Button(string name) => (Button)window.FindName(name);
        string Hint() => ((TextBlock)window.FindName("ElevationHintText")).Text;
        foreach ((string name, ElevationContext context, bool enabled, string hint) in new[]
        {
            ("拆分令牌用户处置自动 UAC", new ElevationContext(false, true), true, "自动请求"),
            ("标准用户可打开管理员窗口", new ElevationContext(false, false), true, "重新扫描"),
            ("管理员状态不重复提权", new ElevationContext(true, true), false, "核对并确认")
        })
        {
            UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, context);
            Check(name, Button("ElevateButton").IsEnabled == enabled && Button("RemediateButton").IsEnabled && Hint().Contains(hint, StringComparison.Ordinal));
        }
        UiPreview.ApplyAccessState(window, new(false, "inert unsafe ACL"), new(false, true));
        Check("便携或不安全安装保留扫描但禁用处置与提权", !Button("ElevateButton").IsEnabled && !Button("RemediateButton").IsEnabled &&
            !Button("RollbackButton").IsEnabled && !Button("DeleteIncidentButton").IsEnabled && Button("QuickScanButton").IsEnabled && Button("ExportButton").IsEnabled);
        UiPreview.ApplyAccessState(window, InstallationSecurityStatus.Protected, new(false, true));
        Check("重新检查刷新处置状态且保留报告与选择", Button("RemediateButton").IsEnabled && window.Findings.Count == 1 &&
            window.Findings[0].IsSelected && ReferenceEquals(typeof(MainWindow).GetField("_lastReport", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(window), report));
        typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [true]);
        Check("扫描或处置中禁止并发提权与刷新", !Button("ElevateButton").IsEnabled && !Button("RefreshInstallationButton").IsEnabled);
        typeof(MainWindow).GetMethod("SetBusy", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [false]);
        window.Close();
    }
}
