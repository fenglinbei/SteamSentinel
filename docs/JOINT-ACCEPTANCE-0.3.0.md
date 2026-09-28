# 0.3.0 后台消息、双语安装器与联合验收

当前说明（2026-09-27）：本文下方保存 9 月 22 日 V2/V3 的历史实测和当时限制。后续基础扫描已停用 AMSI，不因增强缺席显示基础扫描不完整；物理跨屏测试按用户要求暂停。候选 08 的 Windows 10 桌面完整回归为 2358/0/0，Windows 11 安装生命周期已通过；原状 0.2.0 的空状态目录权限仍导致升级拒绝，已批准修复，正在准备候选 09 的真实迁移、安装与最终界面复验。历史通过不能替代新候选验收，尚未公开发布。

Current note (2026-09-27): the following sections preserve the earlier V2/V3 evidence. Baseline scanning now leaves AMSI disabled without treating its absence as incomplete baseline coverage. Physical cross-monitor testing is paused. Candidate 08 passed 2358 Windows 10 desktop self-tests and the Windows 11 installation lifecycle. Migration of unchanged empty 0.2.0 state directories is being repaired and must be verified with candidate 09. Final candidate acceptance and public release remain incomplete.

历史更新：2026-09-22。本记录区分当时候选的实测、保留的失败和发布前缺口，不以第 5 步旧 V4 构建的结果替代当时候选。后台消息与双语安装器已实现；联合验收尚未全部完成。

## 当前候选 V3：目标列修复

| 项目 | 身份 |
| --- | --- |
| 包目录 | `previews/SteamSentinel-0.3.0-preview-e645c27207d4-dirty-5ef39e8d6cef` |
| 源码快照树 | `5ef39e8d6cefa1983748b63c1f1fa4fc72145495` |
| 构建身份 | `0.3.0+e645c27207d406721a67e3d13ae0ec2f7e43449e.dirty.preview.5ef39e8d6cef` |
| 安装器 SHA-256 | `83AA87B3B9DD9DFD3B202D78284B91E3BF22A09ADF00C1CCA4A23F0EBA69A26B` |
| Core SHA-256 | `9EF60BCF3A8FBEA856F3F5941A4E3CB54E42AA19D281B63870FBDC5990025D75` |
| Broker DLL SHA-256 | `813F94C2D242035917BF94CCC9A7CAA19C06F20A4D228A40F64165106E370149` |
| 完整源码回归 | 2,211 通过、0 失败、0 跳过，`preview-build-05.log` 与包内 `SELFTEST-RESULTS.json` |
| 真实 WPF 布局回归 | 英文、简体中文各 357 通过、0 失败；五种尺寸的目标单元格先失败后通过 |
| 安装后实际复验 | Scratch 升级、真实界面扫描/预览/Broker 隔离/复扫及目标列显示通过，27 项证据核验通过 |
| 分发状态 | `UNSIGNED-PREVIEW`；未公开发布，未冻结 RC 或正式发行范围 |

V3 相对 V2 的非文档改动只有 `MainWindow.xaml` 的目标列绑定与 `V0117LayoutTests.cs` 的五项回归断言，Core、Broker、检测规则与状态/原因契约源码没有变化。重新构建后的二进制身份不同，下面三样本感染、恢复与重启证据仍明确归属于 V2，不能描述为 V3 全链条重跑。

证据根目录为工作区 `work/v03-step7-20260921`。V3 在 Scratch 从 V2 原位升级，安装器退出码为 0，八个安装文件哈希与候选一致；升级前后 20 个机器数据文件、两份历史处置摘要、用户语言设置及原隔离样本不变。实际界面重新扫描精确哈希副本，确认后由新身份的 Broker 完成隔离及独立 hosts 阻断，原范围复扫 0 命中。新增仅一份结果、一份隔离清单、一个已知哈希隔离文件和一份用户处置记录；正常对照文件保留。目标列正确显示完整副本路径和 `hosts`，英文结果原因显示正常，Partial 限制保留。

原始事件 `upgrade-Scratch-originals/event-ui-upgrade-installed.json`、`event-ui-upgrade-finished.json` 均通过完整哈希校验，接收器已关闭，无损坏帧、缺块或残帧。核验记录为 `ui-upgrade-verification-v3.json`，实际画面为 `screen-ui-upgrade-targets-fixed-23.png`、`screen-ui-final-product-32.png`。本次没有为显示修复再次执行系统重启。

最终验收说明在 V3 构建后更新，仅改变文档；候选、源码归档和哈希清单未覆盖。交付入口见工作目录 `DELIVERY-20260922.md`。

## 感染全链条与首次交互验收候选 V2

| 项目 | 身份 |
| --- | --- |
| 包目录 | `previews/SteamSentinel-0.3.0-preview-e645c27207d4-dirty-65153b50b02b` |
| 源码快照树 | `65153b50b02b1a2261aad30794785dcc6785ec5b` |
| 构建身份 | `0.3.0+e645c27207d406721a67e3d13ae0ec2f7e43449e.dirty.preview.65153b50b02b` |
| 安装器 SHA-256 | `AE2A613CB289C77E1EAF306ACF779B1B5B8B1A415CC995054240E35EF4B9C8D3` |
| Core SHA-256 | `8AEA7BA01FBFA751364AF7E9CA9DD7370F3E92A46612455112D7B5EEE2F1DD83` |
| Broker SHA-256 | `FF964EE117DAA90BE33A72BF5D2B6E5A3681AE0DAFB6C200AE78D4B86546EE31` |
| 完整源码回归 | 2,206 通过、0 失败、0 跳过，`preview-build-04.log` 与候选内 `SELFTEST-RESULTS.json` |
| 分发状态 | `UNSIGNED-PREVIEW`，已授权隔离实验候选；未公开发布，未冻结 RC 或正式发行范围 |

第一候选 `b3b20510c264`、V2、旧构建、源码快照、只读介质和检查点均保留。本文与英文快速使用说明在 V2 构建之后新增，未改写现有包。

## V2 已通过的安装与界面项目

- `joint-v2-Scratch-status.json` 的 17 项检查全部通过，完整事件来自 `joint-Scratch-part2.capture`，无损坏帧或残帧。
- 英文安装、中文覆盖升级、干净状态安装及重装成功；实际读取 `Inno Setup: Language` 为 `en` / `zhHans`。第一候选读取错误注册表属性而得到 null 的记录仍保留。
- 缺失或篡改中文卫星资源、额外可加载 DLL 均被安装完整性验证拒绝，恢复原内容后可用。
- 15 个旧机器记录文件的哈希保持不变；不可信且非空的状态目录被拒绝，其 ACL 和内容不变；卸载移除程序并保留隔离记录。
- V2 的普通用户界面扫描正常 DemoClock：8 个文件，0 发现；AMSI 失败仍显示未检查原因并保持 Partial。
- 英文详情标签间距修复已在实际虚拟机界面复核。相关真实 WPF 布局测试中英文各 352 项通过，原英文重现失败（351 通过、1 失败）保留。
- 保存下次启动语言时当前英文窗口与报告不变；新 LabAdmin 窗口实际继承当前英文，管理员自己的下次启动偏好仍为 Auto；重新启动 LabUser 应用后中文生效。跨账户重新扫描要求保留。

主要界面证据：`screen-v2-en-unchecked-fixed-01.png`、`screen-v2-language-save-zh-01.png`、`v2-admin-en-ready-01.png`、`screen-v2-admin-language-01.png`、`v2-zh-ready-01.png`。安装器的实际语言选择页面已在下述交互补验中验证。

## 2026-09-22 实际交互补验与目标列修复

Scratch 使用 V2，从真实界面完成双语安装向导检查与安装前取消、LabUser 英文扫描、UAC 取消、LabAdmin 新窗口继承英文并重新扫描、预览取消、确认复选框、真实 Broker 隔离及原范围复扫。专用观察工具没有调用扫描器、规划器或 Broker 引擎。原始事件与屏幕、进程身份及后台记录的 37 项核验全部通过，见 `ui-functional-verification-v2.json`。

- 取消安装、UAC 和预览后，观察范围内的机器文件、样本和记录不变；预览确认框默认未勾选，执行按钮禁用。
- 正常处置包含隔离一个精确哈希副本和独立的 hosts 域名阻断动作。实际 Broker 进程、父管理员进程、计划编号、程序集哈希与机器结果匹配。样本进入可恢复隔离，两份正常对照文件、15 个历史机器文件及原始隔离源保持不变。
- 第二个副本在预览后被替换为 70 字节无害文本。实际 Broker 返回结构化哈希变化原因，拒绝隔离替换文件；该文件保留，界面显示未全部完成。关联 hosts 动作完成，因此此项验证的是文件隔离拒绝，不是整批事务回滚。
- 英文界面按结构化字段显示成功和失败原因，原始中文 `Message` 与状态/原因标识仍保存在结果中。受限扫描和系统检查的 Partial 限制继续显示，不能据此声明整机安全。

交互补验发现处置结果表的目标列错误绑定 `TargetDisplay`，原始记录内目标路径完整但界面空白。源码已改为绑定 `RemediationTargetOutcome.Target`。真实 WPF 单元格回归先在五种窗口尺寸重现失败，修复后中英文各 357 项通过、0 失败；原失败记录保留。此修复不改变状态码、原因码、记录结构或处置逻辑，已生成独立 V3 并核对安装后的实际显示，见本文开头。V2 证据内保留的缺陷描述继续反映其当时状态。

观察工具的问题与产品缺陷分别记录：V1 的安装目录 ACL 判据过严；V2 的进程路径短暂不可读处理不完整；V3–V5 读取错误文本附带 PowerShell 提供程序属性，导致深度 JSON 序列化异常。V6 使用纯文本读取并恢复观察。九个原始事件均已通过长度、分块及整文件哈希验证，11 个损坏重复帧保留，无未完成事件或残帧；接收器已关闭。详见工作目录 `UI-INTERACTIVE-20260922.md`。

## V2 的三样本感染、恢复与重启复验

三台均从已保留的感染加载检查点恢复，并在任何处置前重新观察实际 VPet 模块、Steam 改写和样本成员哈希。使用同一候选的安装器、Core、Broker 与受限 Worker；专用实验驱动不进入产品包。

| 项目 | SmartPet | TianLai | Scratch |
| --- | --- | --- | --- |
| 实际感染加载及精确候选安装 | 通过 | 通过 | 通过 |
| 三处副本共 12 个已知恶意源 | 通过 | 通过 | 通过 |
| 12 项隔离及单独选定的 1 项配置处置 | 通过 | 通过 | 通过 |
| 其余成员哈希与属性保留 | 通过，30 项 | 通过，30 项 | 通过，168 项 |
| 同版本官方基线恢复 | 通过 | 通过 | 通过 |
| 实际系统重启及重启扫描 | 通过 | 通过 | 通过 |
| Steam/VPet 复启与最终扫描 | 补充验收通过，首次脚本失败保留 | 登录后补验通过，首次等待超时保留 | 登录后补验通过，首次等待超时保留 |

每台仅恢复 `steamui/chunk~2dcc5aaf7.js` 一个文件，随后验证 827 个官方基线文件；`steam.cfg` 作为已明确选择的单独配置项处置，不计为恶意源文件。恢复使用哈希固定、同版本的感染前官方介质，不代表产品已经自动执行 Steam 修复。所有扫描的 AMSI 缺口仍保留 Partial。

SmartPet 的首次复启断言错误地要求样本目录内没有任何加载模块。完整诊断显示，官方 VPet 主程序身份正确、模块读取成功，加载的是 4 个未选中处置且哈希未变的数据库依赖；已知恶意源已不存在。修正后的私有补充验证逐项检查精确路径及原始哈希，拒绝已知恶意身份、未跟踪或变化的模块，保留其余成员，并使用当前候选再扫描。未重复隔离、Steam 恢复或系统重启。`sample-SmartPet-v2-status.json` 标记 `passedAfterSupplementalVerification`，保留原 `failure-continuation` 和两次补充诊断。

SmartPet 首次处置事件串口传输丢失 13 字节。补证工具从受保护的虚拟机原始 JSON 读取，通过有界压缩、分块哈希及整文件长度/SHA-256 核验得到完整记录。损坏行是完整原件的严格字节子序列，未修补或拼造 JSON。一个损坏的重复分块也与独立有效副本逐字节对照；原串口数据、拒绝记录和对照均保留。完整原件哈希为 `dc84d73aaf98c3339c066b58359f9e725e73e66a70d3ea1b677e599a70e38972`。传输校验 8 项回归通过。

TianLai、Scratch 的首次 30 分钟桌面等待均超时，原 `failure-continuation` 保留。2026-09-22 用户完成手动登录后，V3 私有补验介质核对了受保护会话、实际重启、LabUser 桌面归属、启动任务及清理后文件状态，然后启动官方 Steam/VPet 并复扫；未重复清理、恢复或重启。两台均标记 `passedAfterSupplementalVerification`。复启判据共 14 项基于实际证据的回归通过，覆盖已知恶意模块、未跟踪模块、哈希/属性变化、模块不可读、源文件复现、Steam 回写，以及不能用本次补验掩盖其他错误的限制。

Scratch 原 `quarantine-verification` 串口事件虽仍是合法 JSON，但一个成员的 `expected` 哈希丢失了 13 个字符。完整原件通过独立分块及整文件校验取回，SHA-256 为 `0ed47647d5925bb3a30befe5d3043b50f5487e60efefe62b13c672b57fbc62ed`；原损坏内容哈希为 `eaa7798082b01eac8d48b56334fdf190b2c326452d21487cb4f18d45f08fd37b`。事件身份、时间和启动身份一致，旧内容是完整原件的严格字节子序列。旧 `sample-Scratch-v2-events/event-quarantine-verification.json` 未覆盖；完整原件位于 `sample-Scratch-v2-verified-originals`。最终判定使用状态文件的 `authoritativeEventFiles`，同时保留 `parsedRecordConflicts` 和差异证据。传输校验现为 12 项回归通过，不接受替换字节、其他事件身份或缺失身份。

三台接收器均已关闭，串口记录分别为 SmartPet 343,520 B、TianLai 250,738 B、Scratch 480,349 B；三台均无未解决的传输冲突、残帧或缺块。产品扫描的 AMSI Partial 限制不因实验验收通过而改变。

## 实验存储维护

2026-09-22 经用户明确批准，移除已完成独立恢复验收且关机的 `SteamSentinel-RestoreCheck-v03`（ID `4c23506b-8444-4248-a052-0a0f38a9b04c`）及 `I:\MalwareLab\RestoreChecks\v03-clean-20260920`。实际释放 38,868,942,848 B，约 36.20 GiB。已先核对全部实验 VHD 父链，确认其他磁盘不依赖该目录；原干净母机、原始导出、准备机、三台样本克隆和其余 31 个检查点均保留，清理后身份及活动磁盘路径复核不变。见 `restore-cleanup-proposal-01.json`、`restore-cleanup-result-01.json`、`current-case-isolation-02.json` 和 `I-STORAGE-REVIEW-2026-09-22.md`。历史环境验收文件记录清理前状态，继续保留。

## 发布前仍需完成

1. 已完成 V3 安装和实际目标显示复验。V2 交互补验覆盖安装语言选择、跨账户重新扫描、UAC 取消、预览及真实 Broker 成功/文件变化失败流程；仍需按最终发行范围补其余故障和宿主关联场景，并按最终候选变化决定复验范围。
2. 补 Windows 10/11、不同 DPI 和完整用户路径矩阵。2026-09-23 已定位本实验环境的 AMSI 初始化故障为精简环境遗漏 `SystemDrive`，完成最小源码修复及实际 Worker 的三次独立验证；Low、Job 和错误/Partial 语义保留。同日完成 DPI 修复：原 10 项失败中的 7 项校正测量判据，3 项修复实际结果行裁切；中英文五档缩放共 3,840 项、完整原生回归 2,240 项通过，1,210 张截图完成非空内容及尺寸核验。跨缩放采用自测窗口 DPI 通知，单显示器环境尚不能代替跨物理屏拖动、远程桌面和 Windows 10 实机验收。现有 V3 安装包未替换，后续候选须按新身份复验。完整证据与边界见 [AMSI 兼容修复](AMSI-COMPATIBILITY-0.3.0.md)及 [DPI 修复](DPI-LAYOUT-0.3.0.md)。
3. 校核双语用户文档和发布说明。V3 源码与实测二进制身份已对应；后续再改代码或安装器须重新打包并按新身份复验必要项目，保留现有候选不覆盖。
4. 在上述结果可审阅后，与用户沟通冻结 Preview/RC 范围、版本身份和已知限制。公开发布继续满足既有签名与审查门槛。

English user instructions: [Quick start](QUICKSTART.en.md). Implementation details: [backend messages](BACKEND-MESSAGES-0.3.0.md), [installer languages](INSTALLER-LANGUAGES-0.3.0.md), [language settings](LANGUAGE-SETTINGS-0.3.0.md).
