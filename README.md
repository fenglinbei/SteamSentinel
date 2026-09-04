# SteamSentinel Steam 红信安全工具

<img src="SteamSentinel.App/Assets/App.png" width="96" height="96" alt="SteamSentinel 应用图标" />

SteamSentinel 是面向 Windows 的本地优先扫描、辨别、隔离与 Steam 恢复工具，针对目前观察到的 Steam / Wallpaper Engine“假红信”诈骗链及相近落地方式。当前版本为 **0.1.16**，适合群内受控测试。构建支持自有组件、安装器与卸载器签名，类型以包内 `SIGNING.txt` 为准，自签名不等于公开受信任的发布者签名。尚未完成外部安全审计，不应直接作为正式公开发行版传播。

它的定位是：让不想临时安装 360、卡巴斯基等完整安全套件的用户，也能快速对当前电脑做一次 Steam 垂直场景检查和可回滚处置。启发式能力不会因为专业杀毒软件存在而关闭，但启发式发现默认不预选，必须由用户核对精确目标后才能隔离。

## 主要能力

已实现本地全 AppID 工坊发现，范围见 [COVERAGE-0.1.14.md](docs/COVERAGE-0.1.14.md)，本版分批处置、4 GiB 核验额度和原范围复查见 [COVERAGE-0.1.16.md](docs/COVERAGE-0.1.16.md)，后续事项见 [ROADMAP.md](docs/ROADMAP.md)。图标来源与重建方式见 [ICONS.md](docs/ICONS.md)。

- 只读检查进程、Run/RunOnce、计划任务、服务、Windows 安全设置、hosts、代理状态及 Steam 客户端完整性风险点。
- 自动发现全部本地 Steam 库中的数字 AppID 工坊项目，支持指定游戏范围，单独适配 Wallpaper 元数据、鸭科夫 MOD、常见 Mods/BepInEx/plugins 和 Steam 插件目录。非工坊游戏私有 MOD 布局不保证全部自动发现。
- 安装包通过 Windows 只读数据库和 CAB 接口分析，LNK 仅读取二进制结构，不启动目标。未支持、损坏、外部分卷与超限内容明确列为未完整扫描。
- 按已知恶意文件身份关联进程模块、Run/RunOnce、任务和服务。可关闭加载恶意组件的正常游戏宿主，不隔离游戏主程序。间接脚本启动链仍供人工复核，不自动删入口。
- 针对本机已确认的恶意 steamprocess 插件，可手选移除精确 Defender/ASR 排除项和禁用关联放行规则，均有配置快照与回滚信息，不重置所有安全设置。
- 快速内容读取预算为 1 GiB，另为小型启动文件保留 128 MiB。完整内容扫描不设默认整轮哈希字节上限，仍有内存、文件数和解压安全限制，不等于无限全盘扫描。优先检查关联落点、插件与 MOD，覆盖记录按目录合并并提供补查方式。下载、桌面、临时目录和运行历史均须用户勾选。
- 按文件魔数识别真实格式，不依赖扩展名，可识别 PE 改名、MP4 尾随载荷和常见脚本。
- 递归检查 ZIP、RAR、7z、tar、gzip、bzip2、xz、zstd 等 SharpCompress 支持的容器，并限制层级、条目数、展开体积和压缩比。
- 遇到加密压缩包时由界面询问密码，可选择当前层、当前外层文件及嵌套包、本次扫描全部包三个复用范围，仅复用成功解密的密码，不破解、不保存、不写入日志，也不通过命令行传递。用户跳过时明确标记为“扫描不完整”。
- 密码窗口会沿用本次选择并说明失败原因，相同内容跳过后不反复询问，扫描结束可点击“重试未解密内容”补充密码。重试只扫描相关外层文件，不代替全机复扫。坏包不会中止后续文件扫描。
- 将内容扫描放在 Low Integrity 受限令牌的独立工作进程中，进程以挂起状态创建，先加入单进程 Windows Job Object，再开始读取不可信内容，安装器还会为该进程添加双向网络阻断规则。
- 管理员窗口也使用 Low 权限扫描组件，不以提权替代隔离。组件启动失败时显示阶段与可取得的退出码，已完成的系统检查仍可导出，未检查内容不会被当作安全。
- 所有处置先生成预览计划，再通过 UAC 管理员 Broker 执行。Broker 会绑定请求者 SID、短时计划 SHA-256、精确路径、文件哈希、目录指纹、注册表当前值和计划任务哈希。
- 文件隔离采用同一已锁定句柄完成哈希、复制、复核和源文件删除，避免在“检查路径”和“管理员操作路径”之间被替换。跨卷目录隔离会做源/副本双向指纹复核，再逐文件按句柄删除。
- 每个隔离事件保留原路径、哈希和动作清单，支持拒绝覆盖式回滚，永久删除不可回滚。
- 默认不上传文件、密码、Steam 账户信息或报告。
- 能识别本次真实样本的 `ServiceApp.exe`、`DesktopNotify.exe`、`notify_bridge.dll`、启动批处理、被改写 steamui chunk 与 `luminovastella.top`，并检查强制红信、游戏重定向、隐藏地址栏和 `steam.cfg` 成对禁更。
- 运行于任意 Steam 库的 Wallpaper Workshop 可执行文件都会进入进程哈希候选。同一路径存在多个进程时，处置计划会先终止全部 PID，再只隔离文件一次。

## 推荐运行方式

1. 从受信任渠道取得 `SteamSentinel-0.1.16-setup.exe`，先对照同目录的 `SteamSentinel-0.1.16-RELEASE-SHA256.txt` 核对哈希。升级前退出旧版主程序和管理员窗口，使用安装包覆盖安装，不要只替换 EXE。
2. 使用安装器安装到固定的 Program Files 目录。默认普通权限扫描，处置时自动请求 UAC，也可点击“打开管理员窗口”主动授权，不需要在快捷方式中手动配置。
3. 首次使用先执行“快速扫描”，随后执行“完整工坊扫描”。单独收到的 MP4、压缩包或安装包可用“扫描文件/目录”。
4. 检查结果顶部的覆盖状态。`Complete` 只表示已完成支持范围内的检查，`Partial` 不能当作“安全”。
5. 已知恶意项会默认预选，启发式项保留可选处置能力但默认不选。核对判定类型、精确目标与哈希/目录指纹后再确认 UAC。
6. 如果动作涉及 Steam 前端，请先完整退出 Steam。异常前端文件与 `steam.cfg` 被隔离后，重新启动 Steam 让官方客户端补全组件，若未自动补全，使用 Steam 官方安装包覆盖安装。
7. 隔离后重启并再次完整扫描。需要恢复时使用“隔离与回滚”，永久删除前应先保留取证副本。

解压 `SteamSentinel-0.1.16-win-x64.zip` 直接运行时，扫描和报告导出仍可使用，但隔离、恢复、永久删除及管理员窗口入口会关闭。只有 Program Files 受保护安装、目录及文件 ACL 检查、安装包 `SHA256SUMS.txt` 全部列出文件的校验同时通过时，程序才开放管理员处置。检查包含 DLL、运行时配置、子目录和清单自身权限，普通用户的读取和执行权限不会被误判为可写。

处置计划仍绑定发起扫描的 Windows 账户。使用管理员账户的普通权限窗口时，处置可直接请求 UAC。标准账户需要点击“打开管理员窗口”，在 Windows 提示中提供管理员凭据，然后在新窗口重新扫描并生成计划。原报告、选择和密码不跨账户传递，原窗口仍保留，取消 UAC 不会丢失结果。若使用另一账户，请确认新扫描包含原用户的 Steam 与工坊目录。没有管理员凭据时不能隔离或恢复，但仍可扫描和导出报告。

“安装检查未通过”与“普通权限窗口”是不同状态。前者不能靠提权绕过，请核对具体缺失或不安全的组件，用安装包修复后点击“重新检查”，该操作不会清空扫描结果。不要为此给普通用户添加安装目录写权限。

## 判定原则

- 已知恶意哈希命中属于高置信度确认，分数为 100。
- 单一扩展名或字符串线索仅供复核，不会直接授权隔离。已分析的高置信组合特征、已复核可疑样本哈希和危险归档路径允许手动隔离，但不会自动预选。
- 压缩包命中不说明主机已经感染，成员内容哈希与外层隔离目标哈希分别记录，外层文件变动后必须重新扫描。
- 不承诺所有格式都能展开，MSI/复合文档目前检查文件哈希并标记未展开，最终载荷未解开或分析不足时保留可疑结论，不冒充确认。
- Wallpaper Engine 内置 `defaultprojects` 不再按自带 EXE/JS 批量告警，应用程序壁纸的 EXE 也不会只凭类型判高危。
- 同名进程只有精确恶意哈希命中才可进入自动处置，仅名称相同一律人工复核。
- 未发现已知威胁不代表对未知恶意代码的绝对保证。
- 代理和证书只做观察或人工复核，本版本不会自动删除用户代理软件或证书。

## 处置边界

Broker 只接受 `%LOCALAPPDATA%\SteamSentinel\Plans` 下的短时 JSON 计划，计划文件名必须与计划 ID 一致，并通过命令行携带的 SHA-256 和请求者 SID 绑定。计划的路径校验、大小检查、哈希与反序列化均绑定到同一锁定句柄。结果只会以不覆盖方式新建在受保护的 `%PROGRAMDATA%\SteamSentinel\Results`，结果路径已存在或无法安全新建时，主程序不会读取该文件。可执行动作包括：终止精确进程、隔离文件/目录、移除已知恶意持久化项、移除已知恶意 Defender 排除项、恢复安全控制、添加精确程序防火墙规则、阻断内置 C2 域名、回滚和删除隔离事件。

处置成功只说明本次计划中的精确目标已被处理，不构成“整台电脑无毒”证明。工具会直接处理已知恶意项，也允许用户处置已复核的启发式项，条件允许时，仍建议再用保持更新的专业安全软件做全盘复核。

含未回滚内容的隔离事件必须至少经历一次系统重启才允许永久删除，界面还要求一次覆盖为 `Complete` 且没有已知恶意项的复扫。生命周期动作必须使用单独计划，避免产生空隔离事件。

## 数据位置

- 用户计划、报告与 Low Integrity 临时区：`%LOCALAPPDATA%\SteamSentinel`、`%USERPROFILE%\AppData\LocalLow\SteamSentinel`
- 管理员隔离区：`%PROGRAMDATA%\SteamSentinel\Quarantine`
- 管理员结果区：`%PROGRAMDATA%\SteamSentinel\Results`
- 规则：编译进程序集的 `default-rules.json`，当前规则版本 `2026.09.04.1`

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
- [本地样本覆盖与限制](docs/SAMPLE-COVERAGE-0.1.5.md)
- [0.1.6 密码交互回归](docs/PASSWORD-REGRESSION-0.1.6.md)
- [0.1.7 安装权限与提权回归](docs/INSTALLATION-REGRESSION-0.1.7.md)
- [0.1.8 管理员扫描启动修复与验证](docs/WORKER-STARTUP-0.1.8.md)
- [签名构建与信任说明](docs/SIGNING.md)
- [发布前清单](docs/RELEASE-CHECKLIST.md)
- [第三方声明](THIRD-PARTY-NOTICES.md)
- [许可证状态](LICENSE-STATUS.md)

## 许可证

本项目由 fenglinbei 按 [Apache License 2.0](LICENSE) 授权，SPDX 标识符为 `Apache-2.0`。版权与归属信息见 [NOTICE](NOTICE)，SharpCompress 与其他第三方组件的独立许可证见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
