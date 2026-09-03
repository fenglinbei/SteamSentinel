# SteamSentinel Steam 红信安全工具

SteamSentinel 是面向 Windows 的本地优先扫描、有限隔离与恢复工具，针对目前观察到的 Steam / Wallpaper Engine“假红信”诈骗链及相近落地方式。当前版本为 **0.1.3**，供发布前审查与受控测试。它尚未完成代码签名和外部安全审计，不应直接作为正式公开发行版传播，也不能替代专业杀毒软件。

## 主要能力

- 只读检查进程、Run/RunOnce、计划任务、服务、Windows 安全设置、hosts、代理状态及 Steam 客户端完整性风险点。
- 自动发现 Steam 多库及 Wallpaper Engine（App ID 431960）创意工坊内容。
- 按文件魔数识别真实格式，不依赖扩展名，可识别 PE 改名、MP4 尾随载荷和常见脚本。
- 递归检查 ZIP、RAR、7z、tar、gzip、bzip2、xz、zstd 等 SharpCompress 支持的容器，并限制层级、条目数、展开体积和压缩比。
- 遇到加密压缩包时由界面询问密码，不破解、不保存、不写入日志，也不通过命令行传递。用户跳过时明确标记为“扫描不完整”。
- 将内容扫描放在独立工作进程中，并用 Windows Job Object 限制子进程数量、内存和生命周期。
- 所有处置先生成预览计划，再通过 UAC 管理员 Broker 执行白名单动作，文件隔离前必须复核精确 SHA-256。
- 每个隔离事件保留原路径、哈希和动作清单，支持拒绝覆盖式回滚，永久删除不可回滚。
- 默认不上传文件、密码、Steam 账户信息或报告。
- 能识别本次真实样本的 `ServiceApp.exe`、`DesktopNotify.exe`、`notify_bridge.dll`、启动批处理、被改写 steamui chunk 与 `luminovastella.top`，并检查强制红信、游戏重定向、隐藏地址栏和 `steam.cfg` 成对禁更。
- 运行于任意 Steam 库的 Wallpaper Workshop 可执行文件都会进入进程哈希候选。同一路径存在多个进程时，处置计划会先终止全部 PID，再只隔离文件一次。

## 直接运行

1. 解压候选包到一个普通、本地、非共享目录。
2. 先核对 `SHA256SUMS.txt`，再运行 `SteamSentinel.exe`。主程序正常扫描不需要管理员权限。
3. 首次使用先执行“快速扫描”，随后执行“完整工坊扫描”。单独收到的 MP4、压缩包或安装包可用“扫描文件/目录”。
4. 检查结果顶部的覆盖状态。只有 `Complete` 表示本轮所选范围被完整读取，`Partial` 不能当作“安全”。
5. 仅勾选已核对的处置项。确认预览后才会出现 UAC，取消 UAC 不会处置。
6. 隔离后重启并再次完整扫描。需要恢复时使用“隔离与回滚”，永久删除前应先保留取证副本。

## 判定原则

- 已知恶意哈希命中属于高置信度确认，分数为 100。
- 扩展名伪装、可疑字符串、异常目录结构等属于线索，不等同于单独定罪，界面会标为需要复核。
- Wallpaper Engine 内置 `defaultprojects` 不再按自带 EXE/JS 批量告警，应用程序壁纸的 EXE 也不会只凭类型判高危。
- 同名进程只有精确恶意哈希命中才可进入自动处置，仅名称相同一律人工复核。
- 未发现已知威胁不代表对未知恶意代码的绝对保证。
- 代理和证书只做观察或人工复核，本版本不会自动删除用户代理软件或证书。

## 处置边界

Broker 只接受 `%LOCALAPPDATA%\SteamSentinel\Plans` 下的短时 JSON 计划，并校验动作类型、路径范围、哈希、规则白名单和重解析点。可执行动作包括：终止精确进程、隔离文件/目录、移除已知恶意持久化项、移除已知恶意 Defender 排除项、恢复安全控制、添加精确程序防火墙规则、阻断内置 C2 域名、回滚和删除隔离事件。

处置成功只说明计划中的高置信目标已被处理，不构成“整台电脑无毒”证明。被隔离的 Steam 前端或 `steam.cfg` 应在专业查杀完成后通过官网重装 Steam 恢复。

含未回滚内容的隔离事件必须至少经历一次系统重启才允许永久删除，界面还要求一次覆盖为 `Complete` 且没有已知恶意项的复扫。生命周期动作必须使用单独计划，避免产生空隔离事件。

## 数据位置

- 用户计划和报告：`%LOCALAPPDATA%\SteamSentinel`
- 管理员隔离区：`%PROGRAMDATA%\SteamSentinel\Quarantine`
- 规则：编译进程序集的 `default-rules.json`，当前规则版本 `2026.09.03.3`

## 从源码构建

需要 .NET SDK 10 和 Windows 10 SDK 19041 或更高版本。

```powershell
dotnet restore .\SteamSentinel.slnx --source https://api.nuget.org/v3/index.json
dotnet build .\SteamSentinel.slnx -c Release --no-restore
dotnet run --project .\SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj -c Release --no-build
```

生成自包含审查包可运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1
```

## 审查入口

- [威胁模型](docs/THREAT-MODEL.md)
- [测试证据](docs/TEST-EVIDENCE.md)
- [发布前清单](docs/RELEASE-CHECKLIST.md)
- [第三方声明](THIRD-PARTY-NOTICES.md)
- [许可证状态](LICENSE-STATUS.md)

## 许可证

本项目由 fenglinbei 按 [Apache License 2.0](LICENSE) 授权，SPDX 标识符为 `Apache-2.0`。版权与归属信息见 [NOTICE](NOTICE)，SharpCompress 与其他第三方组件的独立许可证见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
