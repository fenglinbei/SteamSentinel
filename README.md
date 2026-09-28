# SteamSentinel Steam 红信安全工具

<img src="SteamSentinel.App/Assets/App.png" width="96" height="96" alt="SteamSentinel 应用图标" />

SteamSentinel 是面向 Windows 的本地优先扫描、辨别、隔离与 Steam 恢复工具，针对目前观察到的 Steam / Wallpaper Engine / VPet“假红信”诈骗链及相近落地方式。当前源码为 **0.3.0 开发版**，已补齐 VPet 精确规则、有界家族解码、组件关系、Steam HTML/JS/CSS 检查、ZIP 中文名称绑定及中英文显示。

2026-09-26 的源码构建 `0.3.0+local.basic-final2-20260926` 已通过基础完整回归 **2,348 项，0 失败、0 跳过**，并完成本轮中英文 DPI 验收，见[实施规划](docs/PLAN-0.3.0.md)。**当前暂停系统 AMSI 增强入口及实际调用**；未参与的增强项不使基础扫描显示“扫描不完整”。历史报告保持原样，真正的读取、密码、格式或缺卷等检查缺口仍会显示。无需为基础扫描安装 Norton。

已有双语安装候选仍是此前构建，其完整回归 **2,206 项**及安装、升级、卸载验收记录见[联合验收记录](docs/JOINT-ACCEPTANCE-0.3.0.md)；它没有被当前源码构建替换。新安装包、Windows 10 和跨物理显示器复验尚未完成，也没有新冻结。候选为未签名隔离实验 Preview，尚未公开发布。具体版本、身份与来源以包内 `VERSION.txt`、`SIGNING.txt` 和外层 `RELEASE-METADATA.json` 为准。公开发布模式要求公开受信任的代码签名证书与 RFC 3161 时间戳，否则构建会中止。项目尚未完成外部安全审计，不应把预览包当成正式公开发行版传播。

[English quick start](docs/QUICKSTART.en.md) covers installation, language selection, results, remediation, reports and rollback.

它的定位是：让不想临时安装 360、卡巴斯基等完整安全套件的用户，也能快速对当前电脑做一次 Steam 垂直场景检查和可回滚处置。启发式能力不会因为专业杀毒软件存在而关闭，但启发式发现默认不预选，必须由用户核对精确目标后才能隔离。

## 主要能力

0.3.0 提供“语言 / Language”页，可选择自动 / 简体中文 / English，保存后下次启动生效。Markdown 报告和记录包可单独选择本次导出语言；同一报告对象的 JSON 不因显示语言变化。后台消息已接通可选的稳定消息 ID 和有界参数，来源原文与旧记录保留。中英文使用方法见 [语言设置与导出](docs/LANGUAGE-SETTINGS-0.3.0.md)；当前 3,473 对资源与双语安装器的实现及验收范围见[联合验收记录](docs/JOINT-ACCEPTANCE-0.3.0.md)。

当前源码已接入第三批精确证书/代理动作、依赖阻断、持久病例与跨会话复验，见 [第三批交付说明](docs/EXACT-REMEDIATION-PHASE3.md)。真实样本与重启验收尚未完成，精确配置规则目录暂为空，当前不会仅凭 PAC 或证书名称开放自动修复。第二批的有界补查、离线宿主签名、组件关联及 MSI 静态规则见 [第二批交付说明](docs/RELATED-COMPONENTS-PHASE2.md)。

0.2.0 新增“容器检查”页，显示原始文件、MP4/PE 嵌入归档、成员和分卷的父链、五阶段状态及实际生效预算，可补查原件、明确补卷目录或主动选择恢复输出。普通报告导出只包含元数据。该专项不代表第三批真实修复、MSI/CAB 全部格式或干净 Windows 10/11 安装验收已经完成；历史需求与验收矩阵见 [0.2.0 规划](docs/ARCHIVE-SUPPORT-0.2.0.md)。

0.1.19 保持 0.1.18 的整体设计、原有圆角和小窗口布局，修复表格密度、对齐、留白及按钮对比度，并在同版本内明确扫描结论与补查提示，见 [修复范围说明](docs/COVERAGE-0.1.19.md)。

已实现本地全 AppID 工坊发现，范围见 [COVERAGE-0.1.14.md](docs/COVERAGE-0.1.14.md)，分批处置、4 GiB 核验额度和原范围复查见 [COVERAGE-0.1.16.md](docs/COVERAGE-0.1.16.md)，0.1.17 的安全与发布工程边界见 [COVERAGE-0.1.17.md](docs/COVERAGE-0.1.17.md)，后续事项见 [ROADMAP.md](docs/ROADMAP.md)。图标来源与重建方式见 [ICONS.md](docs/ICONS.md)。

- 只读检查进程、Run/RunOnce、计划任务、服务、Windows 安全设置、hosts、代理状态及 Steam 客户端完整性风险点。
- 自动发现全部本地 Steam 库中的数字 AppID 工坊项目，支持指定游戏范围，单独适配 Wallpaper 元数据、鸭科夫 MOD、VPet 的 `mod`、常见 Mods/BepInEx/plugins 和 Steam 插件目录。VPet 的 `info.lps` 名称和声明编号仅作展示，不能替代实际目录归属。非工坊游戏私有 MOD 布局不保证全部自动发现。
- 安装包通过 Windows 只读数据库和 CAB 接口分析，LNK 仅读取二进制结构，不启动目标。未支持、损坏、外部分卷与超限内容明确列为未完整扫描。
- 按已知恶意文件身份关联进程模块、Run/RunOnce、任务和服务。可关闭加载恶意组件的正常游戏宿主，不隔离游戏主程序。间接脚本启动链仍供人工复核，不自动删入口。
- 针对本机已确认的恶意 steamprocess 插件，可手选移除精确 Defender/ASR 排除项和禁用关联放行规则，均有配置快照与回滚信息，不重置所有安全设置。
- 快速内容读取预算为 1 GiB，另为小型启动文件保留 128 MiB。完整内容扫描不设默认整轮哈希字节上限，仍有内存、文件数和解压安全限制，不等于无限全盘扫描。优先检查关联落点、插件与 MOD，覆盖记录按目录合并并提供补查方式。下载、桌面、临时目录和运行历史均须用户勾选。
- 按文件魔数识别真实格式，不依赖扩展名，可识别 PE 改名、MP4 尾随载荷和常见脚本。
- 对 ZIP、RAR、7z 使用有界分卷与成员完整性适配器，继续检查 MP4 尾随和 PE/RAR SFX 中的归档；tar、gzip、bzip2、xz、zstd 等单流格式可受限展开，但尚无独立完整性验证时明确保留为部分完成。
- 完整/自定义容器默认单成员 8 GiB、逻辑展开 32 GiB、工作预算 64 GiB、深度 12、临时峰值 16 GiB。读取、解码、原生预留、密码尝试、临时空间和时间分别计账；大文件哈希完成不等于默认 32 MiB 字符串检查额度内的内容检查完成。AMSI 增强当前暂停，不调用，也不产生其覆盖缺口或额度提示。
- 遇到加密压缩包时由界面询问密码，可选择当前层、当前外层文件及嵌套包、本次扫描全部包三个复用范围。单密码成功解密后复用；也可明确提供最多 16 个有序候选，按所选范围依次尝试，候选不等同于已验证正确。密码不破解、不保存、不写入日志，也不通过命令行传递。用户跳过时明确标记为“扫描不完整”。
- 密码窗口会沿用本次选择并说明失败原因，相同内容跳过后不反复询问，扫描结束可点击“重试未解密内容”补充密码。重试只扫描相关外层文件，不代替全机复扫。格式或校验失败保留缺口并继续后项；达到整轮资源或时间上限时停止并保留部分结果。
- 可选择本次跳过所有未能解密的加密包：先试适用密码，仍未解开则不再弹窗并记录未检查；新扫描不继承此选择。见 [密码交互说明](docs/PASSWORD-0.1.19.md)。
- 将内容扫描放在 Low Integrity 受限令牌的独立工作进程中，进程以挂起状态创建，先加入单进程 Windows Job Object，再开始读取不可信内容，安装器还会为该进程添加双向网络阻断规则。
- 管理员窗口也使用 Low 权限扫描组件，不以提权替代隔离。组件启动失败时显示阶段与可取得的退出码，已完成的系统检查仍可导出，未检查内容不会被当作安全。
- 所有处置先生成预览计划，再通过 UAC 管理员 Broker 执行。Broker 会绑定请求者 SID、短时计划 SHA-256、精确路径、文件哈希、目录指纹、注册表当前值和计划任务哈希。
- 文件隔离采用同一已锁定句柄完成哈希、复制、复核和源文件删除，避免在“检查路径”和“管理员操作路径”之间被替换。跨卷目录隔离会做源/副本双向指纹复核，再逐文件按句柄删除。
- 每个隔离事件保留原路径、哈希和动作清单，支持拒绝覆盖式回滚，永久删除不可回滚。
- 默认不上传文件、密码、Steam 账户信息或报告。
- 能识别本次真实样本的 `ServiceApp.exe`、`DesktopNotify.exe`、`notify_bridge.dll`、启动批处理、被改写 steamui chunk 与 `luminovastella.top`，并检查强制红信、游戏重定向、隐藏地址栏和 `steam.cfg` 成对禁更。
- 运行于任意 Steam 库的 Wallpaper Workshop 可执行文件都会进入进程哈希候选。同一路径存在多个进程时，处置计划会先终止全部 PID，再只隔离文件一次。

## 推荐运行方式

开发中的第一批“诊断能力与结果解释”已接入源码：可在“代理与证书”页执行本机只读诊断，查看 8 个代理配置来源及当前用户／本机的物理 Root、CA 证书来源。结果会解释“待确认”“暂不支持”和“条件未满足”，不能选择处理的项目会保留原因和下一步；普通信息不计为未处理。诊断不连接外部地址、不修改配置，也不代表确认恶意或处理完成。范围和验证见 [第一批交付说明](docs/TRUST-PROXY-DIAGNOSTICS-PHASE1.md)。

1. 从受信任渠道取得所需版本的安装包，先对照同目录的 `RELEASE-SHA256.txt` 文件及 `RELEASE-METADATA.json` 核对哈希和提交身份（文件名可能带版本前缀）。带 `preview` 或 `dirty` 的文件名不是正式发布。升级前退出旧版主程序和管理员窗口，使用安装包覆盖安装，不要只替换 EXE。
2. 使用安装器安装到固定的 Program Files 目录。默认普通权限扫描，处置时自动请求 UAC，也可点击“打开管理员窗口”主动授权，不需要在快捷方式中手动配置。
3. 首次使用先执行“快速扫描”，随后执行“完整工坊扫描”。单独收到的 MP4、压缩包或安装包可用“扫描文件/目录”。
4. 检查结果顶部的覆盖状态。`Complete` 只表示已完成支持范围内的检查，`Partial` 不能当作“安全”。
5. 已知恶意项会默认预选，启发式项保留可选处置能力但默认不选。核对判定类型、精确目标与哈希/目录指纹后再确认 UAC。
6. 如果动作涉及 Steam 前端，请先完整退出 Steam。异常前端文件与 `steam.cfg` 被隔离后，重新启动 Steam 让官方客户端补全组件，若未自动补全，使用 Steam 官方安装包覆盖安装。
7. 隔离后重启并再次完整扫描。需要恢复时使用“隔离与回滚”，永久删除前应先保留取证副本。

解压便携 `win-x64.zip` 直接运行时，扫描、报告导出和主动容器内容恢复仍可使用，但管理员隔离、隔离回滚、永久删除及管理员窗口入口会关闭。只有 Program Files 受保护安装、目录及文件 ACL 检查、安装包 `SHA256SUMS.txt` 全部列出文件的校验同时通过时，程序才开放管理员处置。检查包含 DLL、运行时配置、子目录和清单自身权限，普通用户的读取和执行权限不会被误判为可写。

处置计划仍绑定发起扫描的 Windows 账户。使用管理员账户的普通权限窗口时，处置可直接请求 UAC。标准账户需要点击“打开管理员窗口”，在 Windows 提示中提供管理员凭据，然后在新窗口重新扫描并生成计划。原报告、选择和密码不跨账户传递，原窗口仍保留，取消 UAC 不会丢失结果。若使用另一账户，请确认新扫描包含原用户的 Steam 与工坊目录。没有管理员凭据时不能执行管理员隔离或隔离回滚，但仍可扫描、导出报告和主动恢复容器内容。

“安装检查未通过”与“普通权限窗口”是不同状态。前者不能靠提权绕过，请核对具体缺失或不安全的组件，用安装包修复后点击“重新检查”，该操作不会清空扫描结果。不要为此给普通用户添加安装目录写权限。

## 判定原则

- 已知恶意哈希命中属于高置信度确认，分数为 100。
- 单一扩展名或字符串线索仅供复核，不会直接授权隔离。已分析的高置信组合特征、已复核可疑样本哈希和危险归档路径允许手动隔离，但不会自动预选。
- 压缩包命中不说明主机已经感染，成员内容哈希与外层隔离目标哈希分别记录，外层文件变动后必须重新扫描。
- 不承诺所有格式都能展开。MSI 使用 Windows 只读数据库与内嵌 CAB 接口检查；外部分卷、特殊压缩或不支持的复合内容会明确标记未完整，最终载荷未解开或分析不足时保留可疑结论，不冒充确认。
- Wallpaper Engine 内置 `defaultprojects` 不再按自带 EXE/JS 批量告警，应用程序壁纸的 EXE 也不会只凭类型判高危。
- 同名进程只有精确恶意哈希命中才可进入自动处置，仅名称相同一律人工复核。
- 未发现已知威胁不代表对未知恶意代码的绝对保证。
- 代理和证书只做观察或人工复核，本版本不会自动删除用户代理软件或证书。

## 处置边界

Broker 只接受 `%LOCALAPPDATA%\SteamSentinel\Plans` 下的短时 JSON 计划，计划文件名必须与计划 ID 一致，并通过命令行携带的 SHA-256 和请求者 SID 绑定。计划的路径校验、大小检查、哈希与反序列化均绑定到同一锁定句柄。结果只会以不覆盖方式新建在受保护的 `%PROGRAMDATA%\SteamSentinel\Results`，结果路径已存在或无法安全新建时，主程序不会读取该文件。可执行动作包括：终止精确进程、隔离文件/目录、移除已知恶意持久化项、移除已知恶意 Defender 排除项、恢复安全控制、添加精确程序防火墙规则、阻断内置 C2 域名、回滚和删除隔离事件。

处置成功只说明本次计划中的精确目标已被处理，不构成“整台电脑无毒”证明。工具会直接处理已知恶意项，也允许用户处置已复核的启发式项，条件允许时，仍建议再用保持更新的专业安全软件做全盘复核。

当前没有 Broker 可独立验证、不可伪造的复扫证明，因此界面的 `Complete` / Full clean 策略不是永久删除的授权边界。Broker 会拒绝删除任何仍含活动记录的隔离事件，包括旧版本创建的事件；只允许清理经过完整结构与路径核验、且所有记录都已标记 `RolledBack` 的空事件。不要为了删除样本而执行回滚；仍需处置的隔离内容应继续保留为证据并等待后续安全删除机制。

## 数据位置

- 用户计划、报告与 Low Integrity 临时区：`%LOCALAPPDATA%\SteamSentinel`、`%USERPROFILE%\AppData\LocalLow\SteamSentinel`
- 管理员隔离区：`%PROGRAMDATA%\SteamSentinel\Quarantine`
- 管理员结果区：`%PROGRAMDATA%\SteamSentinel\Results`
- 规则：编译进程序集的 `default-rules.json`，当前规则版本 `2026.09.20.1`

## 从源码构建

需要仓库 `global.json` 精确指定的 .NET SDK 10.0.400、Windows 10 SDK 19041 或更高版本。生成安装包还需要 Inno Setup 6。依赖锁文件属于源码的一部分；CI 和发布脚本都使用 locked mode，不能静默改写依赖解析结果。

```powershell
dotnet restore .\SteamSentinel.slnx --locked-mode -r win-x64 --source https://api.nuget.org/v3/index.json
dotnet build .\SteamSentinel.slnx -c Release --no-restore
$results = Join-Path $env:TEMP 'SteamSentinel-selftest-results.json'
dotnet run --project .\SteamSentinel.SelfTest\SteamSentinel.SelfTest.csproj -c Release --no-build -- --results $results
Get-Content -LiteralPath $results -Raw
```

在干净工作树上生成明确标记的预览包（默认写到仓库外的 `previews`，绝不覆盖已有目录）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Mode Preview -SkipInstaller
```

只有预览构建可以显式使用 `-AllowDirtyPreview`；此时脚本先拒绝不在源码白名单内的未跟踪文件，再用临时 Git 索引固化快照，文件名与 `BuildIdentity` 同时包含 `dirty` 和源码树 ID。源码包始终由 `git archive` 从该快照生成，不复制忽略文件或任意工作树内容。正式 `-Mode Release` 还要求工作树干净、`HEAD` 精确位于并验证签名的当前版本 `v<版本号>` 注解标签，以及公开受信证书和 HTTPS RFC 3161 时间戳；详情见 [SIGNING.md](docs/SIGNING.md)。

## 审查入口

- [威胁模型](docs/THREAT-MODEL.md)
- [测试证据](docs/TEST-EVIDENCE.md)
- [0.2.0 容器实现与支持边界](docs/ARCHIVE-IMPLEMENTATION-0.2.0.md)
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

### 扫描限制设置

新增“较低／低／中／高／极高／自定义”六项选择，中档保留原默认。大小、递归深度、时间、读取量、内存与临时磁盘等预算可由用户调整，快速与完整／自选模式分别保存，手动补查使用当前设置。每项说明过高或过低的影响，详细数值见 [扫描设置说明](docs/SCAN-SETTINGS.md)。

0.3.0 开发版在扫描前评估资源，遇到可调整的限制时可选择“保持限制”“停止扫描”或“提高并继续”。窗口显示建议额度及风险，默认只用于本次扫描；明确勾选后才保存供以后使用。资源不足或无法确认时不能直接批准。扫描性能可选自动、低占用或高性能，在资源允许的普通文本/脚本上使用最多 2、1 或 4 路；复杂容器仍按原有顺序处理。参见 [资源授权与性能实现](docs/ADAPTIVE-SCAN-0.3.0.md)。
