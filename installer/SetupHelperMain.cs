using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

public sealed class WorkerFirewallRuleSpec
{
    public string Name;
    public string ApplicationName;
    public int Direction; // 1 = inbound, 2 = outbound
}

/// <summary>纯托管 Worker 防火墙规则契约定义、严格校验与 COM 接口操作器。</summary>
public static class SteamSentinelWorkerFirewall
{
    public static WorkerFirewallRuleSpec[] GetContract(string root)
    {
        if (String.IsNullOrWhiteSpace(root)) throw new ArgumentException("InstallRoot is required.", "root");
        string fullRoot = Path.GetFullPath(root).TrimEnd('\\');
        string[,] entries = new string[,]
        {
            { "SteamSentinel.ArchiveWorker.exe", "SteamSentinel ArchiveWorker" },
            { "SteamSentinel.ArchiveWorker.Standard.exe", "SteamSentinel ArchiveWorker Standard" },
            { "SteamSentinel.ArchiveWorker.Compat.exe", "SteamSentinel ArchiveWorker Compat" }
        };
        List<WorkerFirewallRuleSpec> specs = new List<WorkerFirewallRuleSpec>();
        for (int i = 0; i < entries.GetLength(0); i++)
        {
            string exePath = Path.Combine(fullRoot, entries[i, 0]);
            string prefix = entries[i, 1];
            specs.Add(new WorkerFirewallRuleSpec { Name = prefix + " inbound block", ApplicationName = exePath, Direction = 1 });
            specs.Add(new WorkerFirewallRuleSpec { Name = prefix + " outbound block", ApplicationName = exePath, Direction = 2 });
        }
        return specs.ToArray();
    }

    public static void AssertRules(IEnumerable rules, string root)
    {
        if (rules == null) throw new ArgumentNullException("rules");
        List<object> list = new List<object>();
        foreach (object item in rules)
        {
            if (item != null) list.Add(item);
        }

        WorkerFirewallRuleSpec[] contract = GetContract(root);
        foreach (WorkerFirewallRuleSpec expected in contract)
        {
            List<object> matched = new List<object>();
            foreach (object rule in list)
            {
                string ruleName = Convert.ToString(GetProp(rule, "Name"));
                if (String.Equals(ruleName, expected.Name, StringComparison.Ordinal))
                    matched.Add(rule);
            }
            if (matched.Count != 1)
                throw new InvalidOperationException("Missing or duplicate ArchiveWorker block rule: " + expected.Name);

            object actual = matched[0];
            string rawApp = Convert.ToString(GetProp(actual, "ApplicationName"));
            string expandedApp = String.IsNullOrEmpty(rawApp) ? "" : Environment.ExpandEnvironmentVariables(rawApp);
            bool enabled = ConvertToBool(GetProp(actual, "Enabled"));
            int direction = Convert.ToInt32(GetProp(actual, "Direction"));
            int action = Convert.ToInt32(GetProp(actual, "Action"));
            int profiles = Convert.ToInt32(GetProp(actual, "Profiles"));
            int protocol = Convert.ToInt32(GetProp(actual, "Protocol"));
            string localAddr = Convert.ToString(GetProp(actual, "LocalAddresses"));
            string remoteAddr = Convert.ToString(GetProp(actual, "RemoteAddresses"));
            string interfaceTypes = Convert.ToString(GetProp(actual, "InterfaceTypes"));
            object interfacesObj = GetProp(actual, "Interfaces");
            string serviceName = Convert.ToString(GetProp(actual, "ServiceName"));

            if (String.IsNullOrWhiteSpace(expandedApp) ||
                !Path.GetFullPath(expandedApp).Equals(expected.ApplicationName, StringComparison.OrdinalIgnoreCase) ||
                !enabled ||
                direction != expected.Direction ||
                action != 0 ||
                profiles != 2147483647 ||
                protocol != 256 ||
                localAddr != "*" ||
                remoteAddr != "*" ||
                interfaceTypes != "All" ||
                HasNonEmptyInterface(interfacesObj) ||
                !String.IsNullOrEmpty(serviceName))
            {
                throw new InvalidOperationException("ArchiveWorker block rule does not cover its exact host on every profile: " + expected.Name);
            }
        }
    }

    public static void SyncAndVerify(string installRoot)
    {
        Apply(installRoot, true);
    }

    public static void VerifyOnly(string installRoot)
    {
        Apply(installRoot, false);
    }

    static void Apply(string installRoot, bool mutate)
    {
        WorkerFirewallRuleSpec[] contract = GetContract(installRoot);
        if (mutate)
        {
            foreach (WorkerFirewallRuleSpec spec in contract)
            {
                if (!File.Exists(spec.ApplicationName))
                    throw new FileNotFoundException("ArchiveWorker component is missing.", spec.ApplicationName);
            }
        }

        Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
        Type ruleType = mutate ? Type.GetTypeFromProgID("HNetCfg.FWRule", true) : null;
        object policy = Activator.CreateInstance(policyType);
        object rules = null;
        try
        {
            rules = policyType.InvokeMember("Rules", BindingFlags.GetProperty, null, policy, null);
            Type rulesType = rules.GetType();

            if (mutate)
            {
                foreach (WorkerFirewallRuleSpec spec in contract)
                {
                    int safety = 0;
                    while (safety++ < 16 && ContainsExactRuleName(rules, spec.Name))
                        rulesType.InvokeMember("Remove", BindingFlags.InvokeMethod, null, rules, new object[] { spec.Name });
                }

                foreach (WorkerFirewallRuleSpec spec in contract)
                {
                    object newRule = Activator.CreateInstance(ruleType);
                    try
                    {
                        SetProp(ruleType, newRule, "Name", spec.Name);
                        SetProp(ruleType, newRule, "ApplicationName", spec.ApplicationName);
                        SetProp(ruleType, newRule, "Direction", spec.Direction);
                        SetProp(ruleType, newRule, "Action", 0); // NET_FW_ACTION_BLOCK
                        SetProp(ruleType, newRule, "Protocol", 256); // NET_FW_IP_PROTOCOL_ANY
                        SetProp(ruleType, newRule, "Profiles", 2147483647); // NET_FW_PROFILE2_ALL
                        SetProp(ruleType, newRule, "Grouping", "SteamSentinel");
                        SetProp(ruleType, newRule, "Enabled", true);
                        rulesType.InvokeMember("Add", BindingFlags.InvokeMethod, null, rules, new object[] { newRule });
                    }
                    finally
                    {
                        if (Marshal.IsComObject(newRule)) Marshal.FinalReleaseComObject(newRule);
                    }
                }
            }

            List<object> snapshot = new List<object>();
            IEnumerable enumerable = (IEnumerable)rules;
            foreach (object rule in enumerable)
            {
                if (rule != null) snapshot.Add(rule);
            }
            try
            {
                AssertRules(snapshot, installRoot);
            }
            finally
            {
                foreach (object rule in snapshot)
                {
                    if (Marshal.IsComObject(rule)) Marshal.FinalReleaseComObject(rule);
                }
            }
        }
        finally
        {
            if (rules != null && Marshal.IsComObject(rules)) Marshal.FinalReleaseComObject(rules);
            if (policy != null && Marshal.IsComObject(policy)) Marshal.FinalReleaseComObject(policy);
        }
    }

    static bool ContainsExactRuleName(object rules, string targetName)
    {
        IEnumerable enumerable = (IEnumerable)rules;
        foreach (object rule in enumerable)
        {
            if (rule == null) continue;
            try
            {
                string name = Convert.ToString(GetProp(rule, "Name"));
                if (String.Equals(name, targetName, StringComparison.Ordinal)) return true;
            }
            finally
            {
                if (Marshal.IsComObject(rule)) Marshal.FinalReleaseComObject(rule);
            }
        }
        return false;
    }

    static void SetProp(Type type, object instance, string propertyName, object value)
    {
        type.InvokeMember(propertyName, BindingFlags.SetProperty, null, instance, new object[] { value });
    }

    static object GetProp(object instance, string propertyName)
    {
        if (instance == null) return null;
        if (Marshal.IsComObject(instance))
        {
            return instance.GetType().InvokeMember(propertyName, BindingFlags.GetProperty, null, instance, null);
        }
        PropertyDescriptor descriptor = TypeDescriptor.GetProperties(instance)[propertyName];
        if (descriptor != null) return descriptor.GetValue(instance);
        PropertyInfo prop = instance.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
        if (prop != null) return prop.GetValue(instance, null);
        FieldInfo field = instance.GetType().GetField(propertyName, BindingFlags.Public | BindingFlags.Instance);
        return field != null ? field.GetValue(instance) : null;
    }

    static bool ConvertToBool(object value)
    {
        if (value == null) return false;
        if (value is bool) return (bool)value;
        return Convert.ToBoolean(value);
    }

    static bool HasNonEmptyInterface(object interfacesObj)
    {
        if (interfacesObj == null) return false;
        IEnumerable items = interfacesObj as IEnumerable;
        if (items == null) return !String.IsNullOrWhiteSpace(Convert.ToString(interfacesObj));
        foreach (object entry in items)
        {
            if (!String.IsNullOrWhiteSpace(Convert.ToString(entry))) return true;
        }
        return false;
    }
}

/// <summary>安装器预编译原生地位辅助工具入口：负责 MachineState、PayloadMaintenance 与 Worker 防火墙配置。</summary>
public static class SteamSentinelSetupHelperProgram
{
    public static int Main(string[] args)
    {
        if (args == null || args.Length == 0) return 2;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            if (!Environment.Is64BitProcess || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.Error.WriteLine("Administrative x64 privileges are required.");
                return 5;
            }
        }

        string command = args[0];
        Dictionary<string, string> options;
        if (!TryParseOptions(args, 1, out options)) return 2;

        if (command == "state") return RunState(options);
        if (command == "payload") return RunPayload(options);
        if (command == "firewall") return RunFirewall(options);
        return 2;
    }

    static bool TryParseOptions(string[] args, int startIndex, out Dictionary<string, string> options)
    {
        options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if ((args.Length - startIndex) % 2 != 0) return false;
        for (int i = startIndex; i < args.Length; i += 2)
        {
            string key = args[i];
            if (!key.StartsWith("--", StringComparison.Ordinal) || options.ContainsKey(key)) return false;
            options[key] = args[i + 1];
        }
        return true;
    }

    static string Opt(Dictionary<string, string> options, string key)
    {
        string value;
        return options.TryGetValue(key, out value) ? value : null;
    }

    static int RunFirewall(Dictionary<string, string> options)
    {
        string installRoot = Opt(options, "--install-root");
        string action = Opt(options, "--action");
        if (String.IsNullOrWhiteSpace(installRoot) || (action != "sync" && action != "verify")) return 2;
        try
        {
            if (action == "sync") SteamSentinelWorkerFirewall.SyncAndVerify(installRoot);
            else SteamSentinelWorkerFirewall.VerifyOnly(installRoot);
            Console.WriteLine("Verified all six exact ArchiveWorker inbound/outbound block rules.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 22;
        }
    }

    static int RunPayload(Dictionary<string, string> options)
    {
        string mode = Opt(options, "--mode");
        string manifestPath = Opt(options, "--manifest");
        string manifestSha256 = Opt(options, "--manifest-sha256");
        string logPath = Opt(options, "--log");
        string lang = Opt(options, "--lang") ?? "en";
        string prevManifest = Opt(options, "--previous-manifest");
        string prevSha256 = Opt(options, "--previous-manifest-sha256");
        string snapshotOut = Opt(options, "--snapshot-previous-manifest");

        if (String.IsNullOrWhiteSpace(mode) || String.IsNullOrWhiteSpace(manifestPath) ||
            String.IsNullOrWhiteSpace(manifestSha256) || String.IsNullOrWhiteSpace(logPath) ||
            (mode != "Preflight" && mode != "Retire" && mode != "Verify" && mode != "RetireAndVerify"))
        {
            return 2;
        }

        List<string> lines = new List<string>();
        int exitCode = 21;
        FileStream log = null;
        try
        {
            string fullLog = Path.GetFullPath(logPath);
            string pattern = "^payload-maintenance-" + Regex.Escape(mode) + "-[0-9]+\\.log$";
            if (!Regex.IsMatch(Path.GetFileName(fullLog), pattern))
                throw new InvalidOperationException("Unexpected payload log file name.");
            EnsureSafeTempDirectory(Path.GetDirectoryName(fullLog));
            log = new FileStream(fullLog, FileMode.CreateNew, FileAccess.Write, FileShare.Read);

            string[] output = SteamSentinelPayloadMaintenance.Run(
                mode, manifestPath, manifestSha256, prevManifest, prevSha256, snapshotOut);
            lines.AddRange(output);
            exitCode = 0;
        }
        catch (Exception ex)
        {
            Exception current = ex;
            while (current.InnerException != null) current = current.InnerException;
            string code = "InternalFailure";
            string path = "";
            string detail = current.Message;
            MaintenanceException maint = current as MaintenanceException;
            if (maint != null)
            {
                code = maint.Code;
                path = maint.RelativePath;
                if (maint.Operations != null) lines.AddRange(maint.Operations);
            }
            lines.Add(PayloadMessage(lang, code));
            lines.Add(String.Format("Code={0}; Path={1}; Mode={2}", code, path, mode));
            lines.Add("Diagnostic=" + EscapeDisplay(detail));
        }
        finally
        {
            if (log != null)
            {
                try
                {
                    using (StreamWriter writer = new StreamWriter(log, new UTF8Encoding(true), 1024, true))
                    {
                        foreach (string line in lines) writer.WriteLine(line);
                        writer.Flush();
                        log.Flush(true);
                    }
                }
                finally { log.Dispose(); }
            }
        }

        foreach (string line in lines) Console.WriteLine(line);
        return exitCode;
    }

    static int RunState(Dictionary<string, string> options)
    {
        string mode = Opt(options, "--mode");
        string jsonPath = Opt(options, "--log");
        string displayPath = Opt(options, "--display-log");
        string lang = Opt(options, "--lang") ?? "en";

        if ((mode != "Inspect" && mode != "Prepare" && mode != "Verify") ||
            String.IsNullOrWhiteSpace(jsonPath) || String.IsNullOrWhiteSpace(displayPath))
        {
            return 2;
        }

        FileStream jsonStream = null;
        FileStream displayStream = null;
        MachineStateResult result = null;
        int exitCode = 20;
        try
        {
            string fullJson = Path.GetFullPath(jsonPath);
            string fullDisplay = Path.GetFullPath(displayPath);
            string pattern = "^machine-state-" + Regex.Escape(mode) + "-[0-9]+\\.json$";
            if (!Regex.IsMatch(Path.GetFileName(fullJson), pattern) ||
                !String.Equals(fullDisplay, Path.ChangeExtension(fullJson, ".txt"), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Unexpected state log paths.");
            }
            EnsureSafeTempDirectory(Path.GetDirectoryName(fullJson));
            jsonStream = new FileStream(fullJson, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            displayStream = new FileStream(fullDisplay, FileMode.CreateNew, FileAccess.Write, FileShare.Read);

            result = SteamSentinelMachineStateBootstrap.Run(mode);
            if (result == null || !result.Succeeded)
                throw new InvalidOperationException("State verification did not succeed.");
            exitCode = 0;
        }
        catch (Exception ex)
        {
            Exception current = ex;
            while (current.InnerException != null) current = current.InnerException;
            MachineStateException mse = current as MachineStateException;
            if (mse != null && mse.Result != null) result = mse.Result;
            else result = new MachineStateResult { Mode = mode, Succeeded = false, ReasonCode = "StateOperationFailed", Detail = current.GetType().Name };
        }
        finally
        {
            try
            {
                if (result != null)
                {
                    string code = String.IsNullOrEmpty(result.ReasonCode) || !Regex.IsMatch(result.ReasonCode, "^[A-Za-z]{1,64}$")
                        ? "StateOperationFailed" : result.ReasonCode;
                    if (code == "StateOperationFailed" && result.Succeeded) exitCode = 20;

                    List<string> lines = new List<string>();
                    lines.Add(code);
                    lines.Add("migrationRequired=" + (result.MigrationRequired ? "1" : "0"));
                    lines.Add(StateMessage(lang, code));
                    lines.Add(String.Format("Mode={0}; Pending={1}; ChangedThisRun={2}; CreatedThisRun={3}; PreviouslyRestricted={4}; Win32={5}",
                        mode, result.Pending ? 1 : 0, result.ChangedDirectories.Count, result.CreatedDirectories.Count,
                        result.PreviouslyRestrictedDirectories.Count, result.Win32Error));

                    string stateRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SteamSentinel");
                    string installRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SteamSentinel");
                    lines.Add("StateRoot=" + EscapeDisplay(stateRoot));
                    lines.Add("InstallationRoot=" + EscapeDisplay(installRoot));
                    if (!String.IsNullOrEmpty(result.RelativePath))
                        lines.Add("Path=" + EscapeDisplay(result.RelativePath));
                    foreach (string op in result.Operations)
                        lines.Add(EscapeDisplay(op));
                    if (!result.Succeeded && (result.ChangedDirectories.Count + result.CreatedDirectories.Count + result.PreviouslyRestrictedDirectories.Count) > 0)
                    {
                        lines.Add(lang == "zhHans"
                            ? "迁移未完成，已收紧权限不会恢复为旧写权限；安装已停止。"
                            : "Migration did not complete. Restricted permissions were not restored to the old writable permissions. Setup has stopped.");
                    }

                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    serializer.MaxJsonLength = 262144;
                    string json = serializer.Serialize(result);
                    if (Encoding.UTF8.GetByteCount(json) > 262144 || lines.Count > 32)
                        throw new InvalidOperationException("State evidence exceeded bounded budget.");

                    WriteBoundedStream(jsonStream, json);
                    WriteBoundedStream(displayStream, String.Join(Environment.NewLine, lines.ToArray()));
                }
            }
            finally
            {
                if (jsonStream != null) jsonStream.Dispose();
                if (displayStream != null) displayStream.Dispose();
            }
        }
        return exitCode;
    }

    static void WriteBoundedStream(FileStream stream, string text)
    {
        if (stream == null) return;
        using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(true), 1024, true))
        {
            writer.WriteLine(text);
            writer.Flush();
            stream.Flush(true);
        }
    }

    static void EnsureSafeTempDirectory(string directory)
    {
        if (String.IsNullOrEmpty(directory)) throw new InvalidOperationException("Missing log directory.");
        string full = Path.GetFullPath(directory).TrimEnd('\\');
        for (string cursor = full; !String.IsNullOrEmpty(cursor); cursor = Path.GetDirectoryName(cursor.TrimEnd('\\')))
        {
            FileAttributes attr = File.GetAttributes(cursor);
            if ((attr & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Temporary log directory contains a reparse point.");
        }

        DirectorySecurity acl = Directory.GetAccessControl(full);
        string currentSid = WindowsIdentity.GetCurrent().User.Value;
        string[] allowed = { "S-1-5-18", "S-1-5-32-544", currentSid };
        SecurityIdentifier owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner == null || Array.IndexOf(allowed, owner.Value) < 0)
            throw new InvalidOperationException("Installer temporary directory owner is untrusted.");
    }

    static string EscapeDisplay(string value)
    {
        if (String.IsNullOrEmpty(value)) return "";
        StringBuilder sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (c < 32 || c == 127) sb.AppendFormat("\\u{0:X4}", (int)c);
            else sb.Append(c);
            if (sb.Length >= 1500) break;
        }
        return sb.Length > 1500 ? sb.ToString(0, 1500) : sb.ToString();
    }

    static string PayloadMessage(string lang, string code)
    {
        bool zh = String.Equals(lang, "zhHans", StringComparison.OrdinalIgnoreCase);
        if (code == "InvalidManifest") return zh ? "新版文件清单未通过验证。" : "The incoming file list failed validation.";
        if (code == "UnsafePath") return zh ? "文件或目录路径不安全，或存在重解析跳转。" : "A file or directory path is unsafe or redirected.";
        if (code == "UnsafePermissions") return zh ? "已有文件或目录允许不可信修改；未更改其权限。" : "An existing file or directory permits untrusted changes. Its permissions were not modified.";
        if (code == "UnknownFile") return zh ? "发现未识别的旧文件，已保留原件。请复核后再重试升级。" : "An unrecognized obsolete file was preserved. Review it before retrying the upgrade.";
        if (code == "LegacyContentMismatch") return zh ? "已知旧文件的名称相同但内容不符，已保留原件供复核。" : "A known obsolete filename has different content. The file was preserved for review.";
        if (code == "NewPayloadMissing") return zh ? "缺少新版必需文件。" : "A required new file is missing.";
        if (code == "NewPayloadMismatch") return zh ? "新版文件未通过完整性校验。" : "A new file failed its integrity check.";
        if (code == "FileBusy") return zh ? "文件正在使用中，请关闭程序后重试。" : "A file is in use. Close the application and retry.";
        if (code == "FileChanged") return zh ? "文件在验证期间发生变化。" : "A file changed during verification.";
        if (code == "DeleteFailed") return zh ? "无法移除已核实的旧文件，安装未完成。" : "An approved obsolete file could not be removed. Setup did not complete.";
        if (code == "InstallationMissing") return zh ? "安装目录不存在。" : "The installation directory is missing.";
        if (code == "AccessDenied") return zh ? "缺少所需的文件访问权限或管理员权限。" : "The required file access or administrative permission is unavailable.";
        return zh ? "安装文件检查未能完成，请查看安装日志。" : "The installation file check could not complete. Review the setup log.";
    }

    static string StateMessage(string lang, string code)
    {
        bool zh = String.Equals(lang, "zhHans", StringComparison.OrdinalIgnoreCase);
        if (code == "StateReady") return zh ? "受保护的应用状态目录已就绪。" : "Protected application state directories are ready.";
        if (code == "StateDirectoriesWillBeCreated") return zh ? "安装将创建受保护的应用状态目录。" : "Setup will create protected application state directories.";
        if (code == "StateDirectoriesCreated") return zh ? "已创建受保护的应用状态目录。" : "Protected application state directories were created.";
        if (code == "LegacyStateMigrationRequired") return zh ? "检测到无数据弱权限状态目录。安装将限制这些目录的写入权限，仅允许系统和管理员写入；不会自动迁移旧数据。" : "Empty weak state directories were found. Setup will restrict write access to System and Administrators. Old data is not migrated automatically.";
        if (code == "LegacyStateMigrated") return zh ? "已收紧经核验的旧版无数据目录权限；未导入或删除旧数据。" : "Write access on the verified empty legacy directories was restricted. No old data was imported or deleted.";
        if (code == "EmptyStateAclHardened") return zh ? "已将标准 ProgramData 继承的空状态目录权限收紧为受保护访问。" : "Empty ProgramData state directories were hardened to protected permissions.";
        if (code == "LegacyStateContainsData") return zh ? "旧的不安全状态目录含有数据或未知项目。安装已停止并保留原件，请保留日志供支持人员复核。" : "An unsafe old state directory contains data or an unknown item. Setup stopped and preserved it. Keep the log for support review.";
        if (code == "LegacyStateUnsupportedAcl") return zh ? "已有状态目录的所有者或权限模式未经审定，未自动接受这些权限。" : "An existing state directory has an unrecognized owner or permission pattern. Its permissions were not automatically accepted.";
        if (code == "LegacyStateChanged") return zh ? "状态目录在核验期间发生变化。安装已停止，未接受或删除已有数据。" : "A state directory changed during verification. Setup stopped; existing data was not accepted or deleted.";
        if (code == "LegacyStateBusy") return zh ? "状态目录正在使用中，请关闭程序后重试；未终止任何进程。" : "A state directory is in use. Close the application and retry; no process was terminated.";
        if (code == "LegacyStateMigrationPending") return zh ? "上次权限迁移尚未完成，继续前必须重新核验整个固定目录树无数据。" : "An earlier permission migration did not complete. Setup must revalidate the complete empty directory tree before continuing.";
        if (code == "LegacySourceMismatch") return zh ? "已有安装与审定旧包不符，已拒绝自动迁移状态权限。" : "The existing installation does not match an approved package. Automatic state migration was refused.";
        if (code == "LegacySourceChanged") return zh ? "已有安装在核验期间发生变化，安装已停止。" : "The existing installation changed during verification. Setup stopped.";
        if (code == "UnsafeStatePermissions") return zh ? "已有状态目录允许不可信修改，安装已停止。" : "An existing state directory permits untrusted changes. Setup stopped.";
        if (code == "UnsafeStatePath") return zh ? "必需路径发生重解析跳转或并非预期对象，安装已停止。" : "A required path is redirected or is not the expected object. Setup stopped.";
        if (code == "StateDirectoryMissing") return zh ? "缺少必需的受保护状态目录。" : "A required protected state directory is missing.";
        if (code == "StateAccessDenied") return zh ? "无法以所需权限安全打开状态目录。" : "The required state directory cannot be opened safely with the necessary permissions.";
        if (code == "MigrationJournalUnsafe") return zh ? "受保护的安装器迁移记录未通过完整性或权限检查。" : "The protected installer migration record failed its integrity or permission checks.";
        if (code == "MigrationJournalWriteFailed") return zh ? "无法持久化并核验受保护的待完成记录，安装已停止。" : "The protected pending record could not be durably verified. Setup stopped.";
        if (code == "StatePermissionsChangeFailed") return zh ? "无法核验目录权限更改；未回放已经移除的旧写权限。" : "A directory permission change could not be verified. Already restricted permissions were not rolled back.";
        if (code == "StateCreateFailed") return zh ? "无法创建必需的受保护目录。" : "A required protected directory could not be created.";
        if (code == "StateEnumerationFailed") return zh ? "无法完成有界目录检查，安装已停止。" : "The bounded directory inspection could not complete. Setup stopped.";
        if (code == "StateIdentityUnavailable") return zh ? "无法取得核验旧权限所需的本机账户身份。" : "The local account identity needed for legacy permission verification is unavailable.";
        if (code == "StateAdministratorRequired") return zh ? "安装需要管理员权限。" : "Administrative installation is required.";
        if (code == "InvalidStateMode") return zh ? "状态检查模式无效。" : "The requested state-check mode is invalid.";
        return zh ? "无法完成应用状态准备，请保留安装日志供复核。" : "Application state preparation could not complete. Keep the setup log for review.";
    }
}
