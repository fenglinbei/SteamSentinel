using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Xml.Linq;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV0117ReleaseEngineering()
    {
        DirectoryInfo? cursor = new(AppContext.BaseDirectory);
        while (cursor is not null &&
               (!File.Exists(Path.Combine(cursor.FullName, "Directory.Build.props")) ||
                !File.Exists(Path.Combine(cursor.FullName, "SteamSentinel.slnx"))))
        {
            cursor = cursor.Parent;
        }

        Check("0.1.17 发布契约可从构建目录定位", cursor is not null);
        if (cursor is null) return;

        string repository = cursor.FullName;
        XDocument properties = XDocument.Load(Path.Combine(repository, "Directory.Build.props"));
        string version = properties.Descendants("VersionPrefix").Single().Value;
        string minimumTests = properties.Descendants("SteamSentinelMinimumSelfTests").Single().Value;
        bool minimumTestsValid = int.TryParse(minimumTests, out int minimumTestCount) && minimumTestCount >= 795;
        Check("0.1.19 中央版本与机器测试基线唯一", version == "0.1.19" && minimumTestsValid &&
            properties.Descendants("AssemblyVersion").Single().Value == "$(VersionPrefix).0" &&
            properties.Descendants("InformationalVersion").Single().Value == "$(VersionPrefix)+$(SteamSentinelBuildId)");

        using (JsonDocument sdk = JsonDocument.Parse(File.ReadAllText(Path.Combine(repository, "global.json"))))
        {
            JsonElement sdkNode = sdk.RootElement.GetProperty("sdk");
            Check("0.1.17 SDK 精确固定且不滚动", sdkNode.GetProperty("version").GetString() == "10.0.400" &&
                sdkNode.GetProperty("rollForward").GetString() == "disable" && !sdkNode.GetProperty("allowPrerelease").GetBoolean());
        }

        string expectedManifestVersion = version + ".0";
        string[] manifests = ["SteamSentinel.App/app.manifest", "SteamSentinel.Broker/app.manifest"];
        Check("0.1.17 应用清单版本与中央版本一致", manifests.All(relative =>
            XDocument.Load(Path.Combine(repository, relative.Replace('/', Path.DirectorySeparatorChar)))
                .Descendants().Single(element => element.Name.LocalName == "assemblyIdentity")
                .Attribute("version")?.Value == expectedManifestVersion));

        string installer = File.ReadAllText(Path.Combine(repository, "installer", "SteamSentinel.iss"));
        Check("0.1.17 安装器版本与系统下限一致", installer.Contains($"#define AppVersion \"{version}\"", StringComparison.Ordinal) &&
            installer.Contains("MinVersion=10.0.19041", StringComparison.Ordinal) &&
            installer.Contains("OutputBaseFilename={#ArtifactBaseName}-setup", StringComparison.Ordinal) &&
            installer.Contains("SetupIconFile={#PayloadDir}\\SteamSentinel.App\\Assets\\App.ico", StringComparison.Ordinal));
        Check("0.1.17 安装升级清理旧版平铺文档", installer.Contains("{app}\\COVERAGE-0.1.11.md", StringComparison.Ordinal) &&
            installer.Contains("{app}\\COVERAGE-0.1.12.md", StringComparison.Ordinal) &&
            installer.Contains("{app}\\COVERAGE-0.1.16.md", StringComparison.Ordinal));
        int installRunStart = installer.IndexOf("[Run]", StringComparison.Ordinal);
        int uninstallRunStart = installer.IndexOf("[UninstallRun]", StringComparison.Ordinal);
        string installRunSection = installRunStart >= 0 && uninstallRunStart > installRunStart
            ? installer[installRunStart..uninstallRunStart]
            : string.Empty;
        Check("0.1.17 安装器防火墙配置失败即停止", installer.Contains("procedure ConfigureWorkerFirewall", StringComparison.Ordinal) &&
            installer.Contains("if ResultCode <> 0 then", StringComparison.Ordinal) &&
            installer.Contains("if CurStep = ssPostInstall then", StringComparison.Ordinal) &&
            installer.Contains("ConfigureWorkerFirewall;", StringComparison.Ordinal) &&
            !installer.Contains("procedure ConfigureMachineStateAcl", StringComparison.Ordinal) &&
            !installer.Contains("icacls.exe", StringComparison.Ordinal) &&
            !installRunSection.Contains("netsh.exe", StringComparison.Ordinal));

        string[] projects = ["SteamSentinel.App", "SteamSentinel.ArchiveWorker", "SteamSentinel.Broker", "SteamSentinel.Core", "SteamSentinel.SelfTest"];
        Check("0.1.17 所有项目提交有效 NuGet 锁文件", projects.All(project =>
        {
            string lockPath = Path.Combine(repository, project, "packages.lock.json");
            if (!File.Exists(lockPath)) return false;
            using JsonDocument lockFile = JsonDocument.Parse(File.ReadAllText(lockPath));
            return lockFile.RootElement.GetProperty("version").GetInt32() == 1 &&
                lockFile.RootElement.GetProperty("dependencies").EnumerateObject().Any();
        }));

        string workflow = File.ReadAllText(Path.Combine(repository, ".github", "workflows", "windows-ci.yml"));
        Check("0.1.17 CI 强制机器结果与测试计数", workflow.Contains("--results $resultPath", StringComparison.Ordinal) &&
            workflow.Contains("result.passed -lt $minimumTests", StringComparison.Ordinal) &&
            workflow.Contains("result.skipped -ne 0", StringComparison.Ordinal) &&
            workflow.Contains("result.buildIdentity", StringComparison.Ordinal) &&
            workflow.Contains("PSObject.Properties['elapsedMs']", StringComparison.Ordinal));
        Check("0.1.17 CI 强制锁定还原和 whitespace 门禁", workflow.Contains("--locked-mode", StringComparison.Ordinal) &&
            workflow.Contains("dotnet format whitespace SteamSentinel.slnx --verify-no-changes --no-restore", StringComparison.Ordinal));

        string release = File.ReadAllText(Path.Combine(repository, "scripts", "build-release.ps1"));
        string signing = File.ReadAllText(Path.Combine(repository, "scripts", "code-signing.ps1"));
        Check("0.1.17 发布拒绝覆盖并原子落盘", !release.Contains("ReplaceExisting", StringComparison.Ordinal) &&
            release.Contains("[IO.Directory]::Move($stageRoot, $finalBundlePath)", StringComparison.Ordinal) &&
            release.Contains("immutable artifacts are never overwritten", StringComparison.Ordinal));
        Check("0.1.17 源码从受控 Git 快照归档", release.Contains("archive --format=zip", StringComparison.Ordinal) &&
            release.Contains("Assert-UntrackedPreviewAllowlist", StringComparison.Ordinal) &&
            !release.Contains("Get-ChildItem -LiteralPath $solutionRoot -Recurse", StringComparison.Ordinal));
        Check("0.1.17 公开发布签名与 RFC3161 时间戳 fail closed", release.Contains("-RequirePublicTrust:$isPublicRelease", StringComparison.Ordinal) &&
            signing.Contains("'/tr', $Profile.TimestampUrl, '/td', 'SHA256'", StringComparison.Ordinal) &&
            signing.Contains("TimeStamperCertificate", StringComparison.Ordinal));
    }
}
