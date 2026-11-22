# SteamSentinel 分层测试工作流与 CI 门禁说明

本文档说明 SteamSentinel 仓库的三档本地测试脚本（`scripts/Test-Local.ps1`）、Windows CI 并行流水线结构（`.github/workflows/windows-ci.yml`）、统一启动与安装器专项的并发验证方式，以及各阶段强制门禁基线。

## 一、三档本地测试体系（L1 / L2 / L3）

为兼顾日常改码响应速度与发版前全链路确定性，本地验证划分为三个递进档位，统一由 [Test-Local.ps1](../scripts/Test-Local.ps1) 调度（同时兼容 Windows PowerShell 5.1 与 PowerShell 7+）：

| 档位 | 目标定位 | 典型耗时/开销 | 包含检查项 | 适用场景 |
| --- | --- | --- | --- | --- |
| **L1** | 快速开发迭代 | 秒级快速反馈 | 可选构建 + `SteamSentinel.SelfTest` `--fast --timings`（传 `-Filter` 时切为 `--filter <关键词> --timings`） | 日常修改核心逻辑或单模块测试时的即时回归（**不替代提交前全量门禁**） |
| **L2** | 提交前全量门禁 | 完整无跳过全量检查 | 可选构建 + `dotnet format whitespace` 校验 + 全量 SelfTest（同步导出主报告、Watchdog 报告、FindingPriority UI 报告与 `--timings`） | 提交代码、发起 PR 前本地一次性过全量门禁与格式检查 |
| **L3** | 发版级预览全链路 | 完整构建与真实系统机制测试 | 先执行 L2 全量门禁，再调用 `scripts/build-release.ps1 -Mode Preview`（覆盖安装器维护/状态专项、Worker 防火墙契约、自包含发布、原生启动器构建与 `Test-UnifiedStartup.ps1`、可选 Inno Setup 安装器） | 修改原生启动器、安装器脚本、打包/签名脚本或准备候选预览包时（**需要管理员权限**） |

## 二、scripts/Test-Local.ps1 参数与命令示例

### 参数说明

- `-Tier`：`L1`、`L2` 或 `L3`（默认 `L1`）。
- `-Filter`：`string[]`，仅用于 `L1` 按套件名称关键词筛选（支持逗号分隔或字符串数组，对应 SelfTest `--filter`）。`L2`/`L3` 禁止传入 `-Filter`。
- `-Configuration`：`Debug` 或 `Release`（默认 `Debug`）。
- `-NoBuild`：跳过 `dotnet build SteamSentinel.slnx -c <Configuration>`，直接复用意图已构建好的输出产物。
- `-NoParallel`：向 `SteamSentinel.SelfTest` 附加 `--no-parallel`，强制按串行方式逐个执行全部选定套件（用于排查并发竞争问题）。
- `-SkipFormat`：仅影响 `L2`（及 `L3` 前置 `L2`），跳过 `dotnet format whitespace SteamSentinel.slnx --verify-no-changes --no-restore`。
- `-SkipInstaller`：仅在 `L3` 透传给 `scripts/build-release.ps1`，跳过 Inno Setup 安装包编译（生成不含安装器的开发 Preview）。
- `-OutputRoot`：
  - `L1` 下指定时将额外导出 `SELFTEST-L1-RESULTS.json`。
  - `L2` 下指定时保留三份 JSON 报告（`SELFTEST-RESULTS.json`、`WATCHDOG-RESULTS.json`、`FINDING-PRIORITY-UI-RESULTS.json`）；**未指定时自动在 `$env:TEMP` 下建立唯一临时目录，校验完成后自动清理**。
  - `L3` 下透传给 `scripts/build-release.ps1 -OutputRoot` 作为预览包输出根目录。

### 常用命令示例

```powershell
# 1. L1：日常快速自检（默认 Debug 构建 + --fast --timings）
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1

# 2. L1：针对特定套件快速迭代，免去重复构建
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1 -Tier L1 -Filter FirewallVerificationBudget,V018 -Configuration Release -NoBuild

# 3. L1：强制串行兜底排查
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1 -Tier L1 -Filter V016,V018 -NoParallel

# 4. L2：提交前全量门禁（构建 Release + 空白格式检查 + 全量 SelfTest 与分项校验，自动清理临时目录）
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1 -Tier L2 -Configuration Release

# 5. L2：已手动构建后跑全量门禁，并保留机器结果 JSON 到指定目录
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1 -Tier L2 -Configuration Release -NoBuild -OutputRoot C:\Temp\ss-l2-out

# 6. L3（需管理员权限 PowerShell）：先跑 L2，再构建不含安装器的 Preview 产物并验证统一启动与安装器专项
powershell -ExecutionPolicy Bypass -File .\scripts\Test-Local.ps1 -Tier L3 -Configuration Release -SkipInstaller
```

> 说明：在 `-Tier L3` 下若检测到当前 Git 工作树存在未提交改动，`Test-Local.ps1` 会自动为 `scripts/build-release.ps1 -Mode Preview` 附加 `-AllowDirtyPreview`（仍严格执行 `Assert-UntrackedPreviewAllowlist` 白名单校验并生成带 `-dirty-<treeHash>` 标识的 Preview）。

## 三、Windows CI 并行流水线结构（.github/workflows/windows-ci.yml）

CI 工作流拆分为两个无依赖、可同时启动的并行 Job（均运行在 `windows-2025`）：

1. **`build-and-selftest`（解决方案构建、格式与全量 SelfTest）**
   - 检出源码并校验 `global.json`、`Directory.Build.props`、`app.manifest` 与 `installer/SteamSentinel.iss` 版本契约。
   - 安装固定的 `.NET SDK`（`10.0.400`）并启用 NuGet 锁文件缓存。
   - 通过 `actions/cache@v4.2.0` 缓存 WinRAR 7.23 安装包到 `$env:RUNNER_TEMP\winrar-cache`：缓存命中时跳过 `Invoke-WebRequest` 下载；**无论是否命中，每次运行均完整执行 SHA-256 校验、`win.rar GmbH` Authenticode 签名与时间戳校验及 `7.23.0` 版本校验**，验证全部通过后静默安装并核对 `7z.exe` 与 `Rar.exe`。
   - 执行 `dotnet restore SteamSentinel.slnx --locked-mode` 与锁文件 diff 校验、Release 构建与 `ProductVersion` 校验、`dotnet format whitespace SteamSentinel.slnx --verify-no-changes --no-restore`。
   - 运行完整 `SteamSentinel.SelfTest`（传入 `--results $resultPath --timings`），校验 `elapsedMs`、`passed >= SteamSentinelMinimumSelfTests`、`failed == 0`、`skipped == 0`、`version` 与 `buildIdentity`，并上传结果产物。

2. **`unified-startup`（Worker 防火墙契约与统一原生启动验收）**
   - 独立检出源码、校验构建契约并安装同版本固定 `.NET SDK`。
   - 运行 `scripts/Test-WorkerFirewallContract.ps1`（校验 20+ 项防火墙契约且不触碰真实系统防火墙）。
   - 执行 `win-x64` 自包含 `--locked-mode` 还原与锁文件校验，仅发布 `SteamSentinel.App`、`SteamSentinel.Broker` 与 `SteamSentinel.ArchiveWorker` 三个宿主所需项目（无需整解方案全量 Debug/SelfTest 构建及 WinRAR）。
   - 运行 `scripts/build-unified-startup.ps1` 生成与验证 9 个原生/托管宿主并生成 `SHA256SUMS.txt`。
   - 运行 `scripts/Test-UnifiedStartup.ps1` 并强制校验 `passed >= 1`、`failed == 0`、`skipped == 0`，上传结果产物。

## 四、并发提速与不降级安全原则

- **`scripts/Test-UnifiedStartup.ps1`**：
  - 使用基于 `System.Diagnostics.Process` + `ReadToEndAsync()` 的 `Start-Child` / `Wait-Child` 异步辅助，避免重定向管道缓冲区死锁并保留精确退出码与输出。
  - 并发拉起互不依赖的真实宿主探测进程（`real-*-probe`、`real-native-package-preflight` 等），并在其 CLR 启动窗口期内完成无副作用 PE 导入表审计（`real-worker-no-gui-imports`），最后按原始确定顺序写回 `$tests`。
  - 在 `New-Fixture` 中预计算并缓存 `SteamSentinel.exe`、`SteamSentinel.Broker.exe`、`Fixture.exe` 及固定 placeholder 文件的 SHA-256，每次仅计算 `fixture-case.txt` 哈希并按完全一致顺序生成 `SHA256SUMS.txt`。
  - 编译完 `Fixture.exe` 后立即在后台异步启动 `fixture-timeout`（内部睡眠 60s 以触发原生启动器 20s 探针超时），同时以最多 4 并发的有界并发池执行其余 21 个独立目录夹具用例，最终收割 `fixture-timeout` 并按确定顺序写入全部结果。
- **`scripts/build-release.ps1`**：
  - `scripts/Test-InstallerPayloadMaintenance.ps1`（使用 `%TEMP%\SteamSentinel-InstallerTests-*` 且不写注册表）与 `scripts/Test-InstallerMachineState.ps1`（使用快照内 `artifacts\installer-machine-state-tests\*` 与独立 `HKCU\Software\SteamSentinelMachineStateTests\<guid>` 测试键）经确认完全无共享状态竞争，因此在各自独立的 Windows PowerShell 5.1 提权进程中并发执行，并严格各自校验退出码、字段完整性、零失败零跳过以及源码/脚本 SHA-256 绑定。

## 五、强制门禁基线

| 门禁来源 | 校验项与基线要求 |
| --- | --- |
| `Directory.Build.props` | `VersionPrefix` 唯一版本源（当前 `0.3.6`）；`SteamSentinelMinimumSelfTests` 当前为 `3751`（`build-release.ps1` 强制 `>= 2348`，`V0117ReleaseTests.cs` 强制 `>= 3646`） |
| `SteamSentinel.SelfTest` 全量门禁 | `passed >= SteamSentinelMinimumSelfTests`、`failed == 0`、`skipped == 0`、`elapsedMs >= 0`、`version` 与 `buildIdentity` 匹配 |
| SelfTest 同步分项门禁 | `watchdog.passed >= 314`（`failed == 0, skipped == 0`）；`finding-priority.passed >= 141`（`failed == 0, skipped == 0`） |
| `V0117ReleaseTests.cs` 静态契约 | CI 必须原样保留 `--results $resultPath`、`result.passed -lt $minimumTests`、`result.skipped -ne 0`、`result.buildIdentity`、`PSObject.Properties['elapsedMs']`、`--locked-mode` 与 `dotnet format whitespace SteamSentinel.slnx --verify-no-changes --no-restore` |
| `Test-UnifiedStartup.ps1` | 提权/CI 全量执行 31 项用例且要求 `failed == 0`、`skipped == 0`（普通用户本地直跑时因 `Broker` 清单要求 `requireAdministrator` 会跳过 2 项 Broker 探针且不包含 `real-elevated-broker-preflight`，共记录 30 项） |
| `build-release.ps1` 安装器专项 | `InstallerPayloadMaintenance` `passed >= 56`、`InstallerMachineState` `passed >= 43`、`WorkerFirewallContract` `passed >= 20`；均要求零失败、零跳过、`productionRootTouched == false`、`vmOperated == false` 及签发包不可变性复核 |

> 发布提醒：本地 `L1`/`L2`/`L3` 与 CI 全绿用于保证代码回归与构建封装质量，不能替代真实 Windows 10/11、硬件 CET 启用环境及正式代码签名证书下的发布前手工整机验收（详见 [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) 与 [UNIFIED-STARTUP.md](UNIFIED-STARTUP.md)）。
