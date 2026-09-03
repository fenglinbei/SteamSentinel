# SteamSentinel Steam 红信安全工具

SteamSentinel 是面向 Windows 的本地优先扫描、辨别、隔离与 Steam 恢复工具，针对目前观察到的 Steam / Wallpaper Engine“假红信”诈骗链及相近落地方式。当前版本为 **0.1.4 group preview**，适合群内受控测试，尚未完成代码签名和外部安全审计，不应直接作为正式公开发行版传播。

它的定位是：让不想临时安装 360、卡巴斯基等完整安全套件的用户，也能快速对当前电脑做一次 Steam 垂直场景检查和可回滚处置。启发式能力不会因为专业杀毒软件存在而关闭，但启发式发现默认不预选，必须由用户核对精确目标后才能隔离。

## 主要能力

- 只读检查进程、Run/RunOnce、计划任务、服务、Windows 安全设置、hosts、代理状态及 Steam 客户端完整性风险点。
- 自动发现 Steam 多库及 Wallpaper Engine（App ID 431960）创意工坊内容。
- 按文件魔数识别真实格式，不依赖扩展名，可识别 PE 改名、MP4 尾随载荷和常见脚本。
- 递归检查 ZIP、RAR、7z、tar、gzip、bzip2、xz、zstd 等 SharpCompress 支持的容器，并限制层级、条目数、展开体积和压缩比。
- 遇到加密压缩包时由界面询问密码，不破解、不保存、不写入日志，也不通过命令行传递。用户跳过时明确标记为“扫描不完整”。
- 将内容扫描放在 Low Integrity 受限令牌的独立工作进程中，进程以挂起状态创建，先加入单进程 Windows Job Object，再开始读取不可信内容；安装器还会为该进程添加双向网络阻断规则。
- 所有处置先生成预览计划，再通过 UAC 管理员 Broker 执行。Broker 会绑定请求者 SID、短时计划 SHA-256、精确路径、文件哈希、目录指纹、注册表当前值和计划任务哈希。
- 文件隔离采用同一已锁定句柄完成哈希、复制、复核和源文件删除，避免在“检查路径”和“管理员操作路径”之间被替换。跨卷目录隔离会做源/副本双向指纹复核，再逐文件按句柄删除。
- 每个隔离事件保留原路径、哈希和动作清单，支持拒绝覆盖式回滚，永久删除不可回滚。
- 默认不上传文件、密码、Steam 账户信息或报告。
- 能识别本次真实样本的 `ServiceApp.exe`、`DesktopNotify.exe`、`notify_bridge.dll`、启动批处理、被改写 steamui chunk 与 `luminovastella.top`，并检查强制红信、游戏重定向、隐藏地址栏和 `steam.cfg` 成对禁更。
- 运行于任意 Steam 库的 Wallpaper Workshop 可执行文件都会进入进程哈希候选。同一路径存在多个进程时，处置计划会先终止全部 PID，再只隔离文件一次。

## 推荐运行方式

1. 从受信任渠道取得 `SteamSentinel-0.1.4-setup.exe`，先对照同目录的 `SteamSentinel-0.1.4-RELEASE-SHA256.txt` 核对哈希。
2. 使用安装器安装到固定的 Program Files 目录。主程序扫描仍以普通权限运行，只有确认处置时才触发 UAC。
3. 首次使用先执行“快速扫描”，随后执行“完整工坊扫描”。单独收到的 MP4、压缩包或安装包可用“扫描文件/目录”。
4. 检查结果顶部的覆盖状态。只有 `Complete` 表示本轮所选范围被完整读取，`Partial` 不能当作“安全”。
5. 已知恶意项会默认预选，启发式项保留可选处置能力但默认不选。核对判定类型、精确目标与哈希/目录指纹后再确认 UAC。
6. 如果动作涉及 Steam 前端，请先完整退出 Steam。异常前端文件与 `steam.cfg` 被隔离后，重新启动 Steam 让官方客户端补全组件；若未自动补全，使用 Steam 官方安装包覆盖安装。
7. 隔离后重启并再次完整扫描。需要恢复时使用“隔离与回滚”，永久删除前应先保留取证副本。

解压 `SteamSentinel-0.1.4-win-x64.zip` 直接运行时，扫描和报告导出仍可使用，但隔离、恢复与永久删除会关闭。只有 Program Files 受保护安装、目录 ACL 检查和三组件 `SHA256SUMS.txt` 校验同时通过时，程序才开放管理员处置。

处置计划会绑定发起扫描的 Windows 账户。管理员账户可直接确认 UAC，标准账户若在 UAC 中输入另一管理员账户的凭据，Broker 会因账户 SID 不一致而拒绝执行。此时仍可使用扫描与报告功能，若要处置，请切换到实际管理员账户重新扫描并生成计划。

## 判定原则

- 已知恶意哈希命中属于高置信度确认，分数为 100。
- 扩展名伪装、可疑字符串、异常目录结构等属于启发式线索，不等同于单独定罪。它们仍可由用户手动选择隔离，但不会自动预选。
- Wallpaper Engine 内置 `defaultprojects` 不再按自带 EXE/JS 批量告警，应用程序壁纸的 EXE 也不会只凭类型判高危。
- 同名进程只有精确恶意哈希命中才可进入自动处置，仅名称相同一律人工复核。
- 未发现已知威胁不代表对未知恶意代码的绝对保证。
- 代理和证书只做观察或人工复核，本版本不会自动删除用户代理软件或证书。

## 处置边界

Broker 只接受 `%LOCALAPPDATA%\SteamSentinel\Plans` 下的短时 JSON 计划，计划文件名必须与计划 ID 一致，并通过命令行携带的 SHA-256 和请求者 SID 绑定。计划的路径校验、大小检查、哈希与反序列化均绑定到同一锁定句柄。结果只会以不覆盖方式新建在受保护的 `%PROGRAMDATA%\SteamSentinel\Results`，结果路径已存在或无法安全新建时，主程序不会读取该文件。可执行动作包括：终止精确进程、隔离文件/目录、移除已知恶意持久化项、移除已知恶意 Defender 排除项、恢复安全控制、添加精确程序防火墙规则、阻断内置 C2 域名、回滚和删除隔离事件。

处置成功只说明本次计划中的精确目标已被处理，不构成“整台电脑无毒”证明。工具会直接处理已知恶意项，也允许用户处置已复核的启发式项；条件允许时，仍建议再用保持更新的专业安全软件做全盘复核。

含未回滚内容的隔离事件必须至少经历一次系统重启才允许永久删除，界面还要求一次覆盖为 `Complete` 且没有已知恶意项的复扫。生命周期动作必须使用单独计划，避免产生空隔离事件。

## 数据位置

- 用户计划、报告与 Low Integrity 临时区：`%LOCALAPPDATA%\SteamSentinel`、`%USERPROFILE%\AppData\LocalLow\SteamSentinel`
- 管理员隔离区：`%PROGRAMDATA%\SteamSentinel\Quarantine`
- 管理员结果区：`%PROGRAMDATA%\SteamSentinel\Results`
- 规则：编译进程序集的 `default-rules.json`，当前规则版本 `2026.09.03.3`

## 从源码构建

需要 .NET SDK 10、Windows 10 SDK 19041 或更高版本。生成安装包还需要 Inno Setup 6。

```powershell
dotnet restore .\SteamSentinel.slnx --source https://api.nuget.org/v3/index.json
dotnet build .\SteamSentinel.slnx -c Release --no-restore
dotnet run --project .\SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj -c Release --no-build
```

生成自包含便携扫描包、源码包、安装包和发布哈希可运行：

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
