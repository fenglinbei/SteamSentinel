# 0.3.0 第 5 步：隔离克隆清理与恢复验证

当前状态（2026-09-28）：`v0.3.0-preview.2` 自签名预发布版已交付，见[发布说明](RELEASE-0.3.0.md)。下文保留第 5 步原 v4 的感染、隔离、恢复和重启证据；不将其冒充当前安装包完整重测。“英文支持仍在第 6 步”等描述属于 9 月 21 日历史状态。

更新时间：2026-09-21。状态：第 5 步的本轮隔离克隆验证已完成。修复后的 v4 运行中，三个样本均通过实际加载、13 项隔离、Steam 恢复、系统重启复扫和官方 Steam/VPet 再启动检查，非处置成员哈希未变。最终结果为 `v4-final-acceptance.json`，三台状态及证据哈希封存于 `v4-final-sealed.json`。完整源码回归为 1,940 通过、0 失败、0 跳过。产品界面、安装升级、自动恢复等边界仍须单独验收；英文支持仍在第 6 步，尚未制作或发布新版安装包。下文保留早期失败与修复记录，最新结果见“v4 重启与再启动验收”。

## 环境与证据边界

- 保留原 `Clean-Offline-v03-20260920` 基线、校验过的导出和恢复检查 VM。准备克隆 `SteamSentinel-v03-Prep` 已封存，再独立导出三个新 ID 的测试克隆。
- SmartPet、TianLai、Scratch 克隆的网卡均未连接交换机。来宾 PowerShell Direct、Guest Service Interface、远程桌面及文件共享服务停止并禁用；时间同步关闭，保持 Secure Boot/vTPM。
- 样本通过逐成员哈希核验的只读 ISO 进入指定克隆。样本暴露标志在介质挂载前写入，之后禁止在宿主挂载该克隆磁盘，也不重新启用 PowerShell Direct。
- 来宾仅接受封存前写入的控制文件 SHA-256 白名单；每个阶段在执行前消费一次。证据经只接收的命名管道串口送出，限制单条 1 MiB、总量 128 MiB，不执行来宾返回内容。原捕获文件保留，后续重连另存分段。
- 所谓“工坊副本”为指定目录中的模拟副本（`999000001`—`999000003`），没有真实订阅或联网重新下载验收。

私有证据目录为工作区 `work/v03-step5-20260920`。VM 磁盘和导出在 `I:\MalwareLab\Step5`；同一物理盘上的副本不等于另盘灾备。

## 构建与干净对照

私有 self-contained 测试包包含 480 个文件，保护目录及全清单哈希已在三个干净克隆中核验。原 v2 SelfTest DLL SHA-256 为 `33156F0E68CE87B1B333359EF6809FF2F70B282E6CFBE6367656FFD754AFEDE1`，Core 为 `D77B1B3D54B15ECAE10BC733B064FA48FE7343CEAA8EC6641815BE2E0EFFDB08`。该 Core 是 RID 发布产物，不能与第 4 步框架依赖构建的文件哈希混作同一构建。后文记录 v3 实验驱动更新，Core 未变化。

本步包含私有实验驱动、诊断部署路径支持及下文记录的 Broker 只读文件隔离修复。驱动调用真实 Low Worker、规划器及 BrokerEngine，已知恶意 DLL 隔离限定为指定目录及完整 SHA-256；另有明确记录的实验配置文件选择。它以实验管理员身份执行引擎，**不代表普通用户界面、UAC、取消操作或产品宿主关联流程通过**。

干净对照结果：

- 官方 DemoClock 8 个文件、919,942 B，无已知恶意或可处置项；覆盖如实为 `Partial`。
- 官方 VPet MOD 范围扫描 6,699 个文件、1,375,775,318 B，197 个归档成员，无已知恶意项；干净 Steam 检查无篡改发现。
- 同一构建、同一 Defender 提供程序下，LabUser 的 Medium 探针对正常文本及 DLL 完成 AMSI 初始化、会话和扫描。Low Worker 在初始化阶段返回 `0x80070103`（十进制 `-2147024637`），尚未到扫描阶段。原因未定，不能因阴性结果消除覆盖缺口，也不提升 Worker 权限或关闭防护来获得通过结果。

相关证据：`clean-checks-2.json`、`clean-guest-evidence/`、`lab-build-v2-manifest-final.json`、`harness-v2-*.json` 和 `clean-package-manifest-verification.json`。

## SmartPet 实际运行

测试 VM：`SteamSentinel-v03-SmartPet`，ID `c560b07c-4642-4f48-9f2d-684394114b6c`。

安装阶段把 14 个文件分别放入游戏 MOD 目录、模拟工坊目录和手动副本目录。安装未加载扫描检出 12 个恶意组件，Steam 的 827 个基线文件未变、`steam.cfg` 不存在。

经 LabUser 桌面会话启动官方 VPet 后，2026-09-20 18:06 的串口证据记录到 `SmartPet.dll` 在 VPet 进程的模块列表中，并观察到下列真实文件变化：

| 文件 | 加载后的 SHA-256 |
| --- | --- |
| `steamui/chunk~2dcc5aaf7.js` | `76CFCA6B71CF761E186DEFAC54912753D19403A279B5078E1C4E37C77AE30449` |
| `steamui/index.html` | `EAC496118509FC229741057B599FAFCBF34395C2231D6F95DDCF699888391D65` |
| `steamui/sp.js` | `19563666A78C70CAC8B6FAB8854B64C4F6AF87FFA12543E6F09A9B7C0D17C1FD` |
| 新增 `steam.cfg`，68 B | `C9799659EC6E3E786F68D73EEC26E7EB1190708CAAD875711096C98F1AAC4E24` |

配置文件哈希与样本静态字符串构成的两个 CRLF 行完全一致：`BootStrapperInhibitAll=enable`、`BootStrapperForceSelfUpdate=disable`，无 BOM。干净基线中没有此文件，恢复时必须单独处理，不能只替换 JS/HTML 后就宣称完成。

加载后扫描完成，仍检出三处共 12 个恶意组件，并检出 `STEAM-CFG-UPDATE-SUPPRESSION-PAIR`、`STEAM-UI-SEMANTIC-TAMPERING` 和 `VPET-STEAM-UI-CHAIN`。多文件关联证据核验了 HTML 入口引用、chunk 路由和 sp.js 定义；日期门控只记录存在，没有声称触发未来日期下的假通知。

实时防护保持开启，此次观察未报告 Defender 检出。这不代表样本无害，也没有验证凭据上传或外部服务响应。

已保存两个检查点：

- 安装未加载：`e4b619ec-e9e2-44c6-800b-4db58e2184b1`。
- 加载后：`45b634b7-9598-432a-8062-7d3d37c5d4b3`。

隔离介质已挂载，但截至当前记录尚无 `source-quarantine` / `after-quarantine` 完成证据。控制台黑屏、串口无新事件。已另存异常状态检查点 `69af5d08-e963-44eb-ab3a-648a2d92fa6d`；随后尝试恢复加载后检查点，Hyper-V 明确报告其虚拟机身份无权读取 `SmartPet-load.iso`（`0x80070005`）。这是已确认的介质权限问题，尚不能单凭此错误认定此前黑屏的唯一原因。原捕获及全部失败记录均保留，不能把宿主“已挂载”当作来宾“已清理”。

用户明确批准读取后，已于 19:17 为三个克隆分别授予各自 7 张 ISO 的 Read 权限，并复核全部 21 个文件没有获得写权限或目录继承。19:18 成功恢复 SmartPet 的加载后检查点；该诊断恢复不计入清理后重启验收。授权范围、应用和核验记录分别为 `media-read-access-proposal.json`、`approved-media-read-complete.json`、`media-read-access-verified.json`。

随后发现安装之外多个控制 ISO 的主卷描述完全相同：卷标、创建时间、卷大小和描述块哈希一致。为排除来宾沿用旧盘缓存，已为 21 个镜像设置唯一卷标和卷时间戳。逐字节反向核验证明修改只涉及主卷/补充卷描述中的 6 个元数据字段，其余目录记录、控制文件、样本及恢复数据完全不变；原文件路径及已批准 ACL 保留。原镜像另存于 `iso-original-preserved/`，新旧哈希与范围见 `unique-volume-media-proposal.json`，应用记录为 `unique-volume-media-applied.json`，当前介质清单为 `media-images-unique-volume.json`。未在宿主挂载样本镜像或来宾磁盘。

### 实际隔离尝试：机器状态保护前置失败

唯一卷标介质挂载后，来宾返回了 `hosts-stopped` 及明确失败事件，说明新的控制阶段已被读取。实验驱动完成扫描和精确文件计划后，`MachineStateSecurity.EnsureProtectedRoots()` 拒绝继续：`机器状态目录在 ACL 收紧前不可信：安装对象允许非受信任账户写入：SteamSentinel`。尚未进入 Broker 隔离动作，不能计为清理成功。

对未暴露样本、关机状态下的 TianLai、Scratch 分别进行只读检查，确认 `C:\ProgramData\SteamSentinel`、`Quarantine`、`Results`、`BrokerTemp` 均为空，但继承了 ProgramData 的普通用户创建权限。当前安装器 `[Dirs]` 也列有这些目录的权限声明；本次实测表明仅检查程序安装目录不足以验收实验部署，机器状态目录必须在投放样本前单独通过产品检查。不能把污染后的目录直接收紧 ACL 后当作可信旧数据使用。

用户明确批准 `clean-machine-state-acl-proposal.json` 中的 8 个空目录及干净盘重跑后，20:00 分别完成 TianLai、Scratch 的权限准备。复核确认 SYSTEM/Administrators 全权、普通用户只读浏览、BrokerTemp 不向普通用户开放，且继承已关闭；应用前 8 个目录均为空。记录为 `TianLai-clean-machine-state-prepare.json` 和 `Scratch-clean-machine-state-prepare.json`。此前自动审批拒绝没有执行写入，本次在获得具体授权后完成。

私有 v3 驱动已部署并核验：新增投放前 `preflight`，直接调用现有安装目录和机器状态安全检查；增加明确选择已观察到的禁更配置的实验操作，要求完整固定 SHA-256、安装前配置不存在、Steam 多文件关联证据同时成立，继续保持配置 `IsKnownMalware=false`。原 Core、App、Broker 与 Worker 二进制未改变，480 行清单中仅 SelfTest DLL/PDB 变化。SelfTest DLL SHA-256 为 `BCDD4612225577D0AA6AE5A26177AC96F81BB740D91D01333BB97B0B9140A4E3`，清单为 `0A59405EC99F0B8B9FFBC5CFF1A0B24486945A55D879B4CD5D1E2D4EC450A6A0`。宿主执行 `preflight` 被环境守卫拒绝，退出码 1；三台来宾启动后的相同检查均退出 0，程序与机器状态保护字段均为 true。该结果只证明前置条件通过，不能代替处置验收。

SmartPet 沿用 VM ID，从修正且未暴露样本的 TianLai 复制两层独立磁盘、逐文件校验 SHA-256 后改接新盘。新磁盘链完全位于 `SmartPet/clean-rerun-v3/VHDs`，旧感染盘从未挂载、删除或修改，全部 5 个原检查点保留。失败现场为 `4e705950-a3f8-4bf4-9756-f9c81680f0ee`；成功准备记录为 `SmartPet-v3-clean-disk-2.json`。第一轮仅在只读容量计算处遇到 PowerShell 兼容错误，未修改 VM 或磁盘，失败记录另存。克隆的历史暴露标志保持 true，新增独立的 v3 当前磁盘运行标志防止历史被覆盖。

v3 采集脚本已部署，先持久保存事件再发送串口，并保留非零退出码。宿主按事件 UUID 去重，拒绝同 UUID 不同内容，忽略正在写入的最后一个不完整帧；三个验证场景全部通过，见 `evidence-parser-validation.json`。三台克隆均在预检成功后才挂载样本介质，继续保持网卡断开和受限串口输出。

SmartPet 的首次安装扫描串口帧出现字符缺失。保留损坏帧原文及其 SHA-256，在安装未加载状态另存检查点后正常关闭、启动来宾，收到预先持久化的完整原事件。宿主仅接受同事件 ID 的完整重发，并核验原损坏帧只缺少字符，未猜测或补写 JSON。实际重发核验见 `SmartPet-v3-serial-replay-verified.json`；完整重发、缺少重发、同 ID 不同载荷三个验证场景通过，见 `damaged-frame-replay-validation.json`。这次诊断重启不属于清理后的重启验收。后续审计发现 v3 证据目录仍有 LabUser 写权限，不能称为受保护证据目录，详见下文修正。

截至 20:29，三台 v3 来宾均已完成安装未加载扫描，退出码 0，各检出 12 个已知恶意 DLL；三处副本数为 3，SmartPet/TianLai 每份 14 个文件，Scratch 每份 60 个文件。安装阶段 827 个 Steam 基线文件均未变化、`steam.cfg` 不存在。三台都已保存 v3 安装阶段检查点，返回 `waiting-labuser-login`，待手动 LabUser 登录后继续实际加载。当前 v3 尚无隔离、Steam 恢复或清理后重启通过结果。汇总为 `v3-rerun-status.json`。

## v3 实际加载及隔离失败

用户登录后，22:57 左右三个克隆均在官方 VPet 进程中观察到对应插件模块。SmartPet 改写 `steamui/index.html`、`steamui/sp.js`、`steamui/chunk~2dcc5aaf7.js`；TianLai、Scratch 观察到 chunk 改写。三者都新增 68 字节 `steam.cfg`，SHA-256 为 `C9799659EC6E3E786F68D73EEC26E7EB1190708CAAD875711096C98F1AAC4E24`，包含成对禁更设置。其安装前均不存在该配置，827 个 Steam 文件均匹配干净基线。

SmartPet 的加载后扫描检出 12 个已知源及完整 Steam UI 关联；Scratch 检出 12 个已知源和 chunk 语义篡改，未满足完整 UI 关联。TianLai 的加载观察有效，但加载后扫描串口帧损坏，不能认定扫描完成。原始捕获均保留，未补造结果。

SmartPet 在停止经路径核验的 Steam/VPet 进程后尝试 13 项处置。事件 `9ddb456d-a700-4933-83df-0fa188377041` 中，12 个恶意 DLL 备份建立后删除失败、原文件仍在，只有单独复核选择的 `steam.cfg` 隔离成功。引擎 `Success=false`、退出码 1；`Disposition=Completed` 不能解释为清理成功。Steam 恢复与验收重启未执行。失败详情保存在 `serial-SmartPet-v3-part2.capture`。

只读无害文件能复现相同句柄删除错误（Win32 5）。文件从只读 ISO 复制而来是疑因；v3 未逐个采集源文件属性，不能把推断当作直接证据。Broker 现在先申请写属性权利，权限不允许时退回原读/删除权利；普通删除遇到只读导致的拒绝时，用同一已验证句柄申请忽略只读属性并保留映像占用检查。不更改源属性或 ACL，不使用 POSIX 删除，不按路径重新打开源。失败消息补充 Win32 错误码。依据见 [Microsoft 文件删除标志](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex)与[文件系统访问权限语义](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4c26c8cb-5a8f-4339-a372-b315c4974131)。

无害专项 `lease-regression-after2/results.json` 为 **6 通过、0 失败、0 跳过**，覆盖普通文件、只读、只读+隐藏+系统、备份哈希错误、普通文件写属性权限拒绝及只读文件写属性权限拒绝。真正样本的成功隔离仍须新来宾结果。

## v4 干净重跑准备及证据修正

审计发现，最早的干净中权限测试给旧 `Evidence` 目录授予了 LabUser Modify，封存脚本未撤回。因此 v3 记录只能作为观察资料，不再用作可信的管理员动作依据。v4 在从未暴露样本的干净盘创建全新的 `C:\Lab\Step5\EvidenceV4`，SYSTEM/Administrators 才可写；处置前复核目录、文件及其父路径的所有者、ACL、重解析点和运行标识。旧记录不迁入新信任域。

三台 v3 运行现场分别保存标准检查点与 VM 状态；旧盘、旧检查点全部保留且不在宿主挂载。新 v4 双层磁盘分别从已校验的准备导出复制，独立重设父盘，只有这些从未接触样本的新盘在宿主进行离线部署。记录为 `v4-clean-copies.json`、`v4-clean-deployment.json`。三个新盘均核验 480 个程序文件、四个空机器状态目录和新证据目录。

v4 包中仅 Broker DLL/PDB 与私有 SelfTest DLL/PDB 相对 v3 变化，Core/App/Worker 不变。Broker SHA-256 为 `542DEB24CE140C026F5F79F899029FF826587E2BAB156B9581B615456A5FA8C0`，清单 SHA-256 为 `AA58A4B93EC48F538D6541DFA1146B206B787E04A9B7FA65BB97B0409A82A33F`。宿主调用实验驱动仍被 STEAMLAB/Hyper-V 环境守卫拒绝。

该首个 v4 包未启动来宾：完整回归得到 **1,939 通过、1 失败、0 跳过**，失败为原生宿主权限环境下的只读文件写属性拒绝用例。不能依赖内核对扩展删除标志的权限行为保持一致；后续修复明确记录初次打开是否成功取得 `FILE_WRITE_ATTRIBUTES`，退回原权限的句柄不能使用忽略只读选项。相同原生环境下的六项专项全部通过，见 `lease-v4b-native/results.json`。

修正的 v4b 包仍用于新的 v4 实验运行；Broker SHA-256 为 `24B86965324068C9A9069467E508229F0E146187C04FA08A04838DB1D52F18C2`，SelfTest 为 `CF25074FEC9B4DDEB410C710718DE8454281B5DE73A6609F123E6274101CB0D8`，清单为 `1421D5C8AC1D0D83F0B7BFC3CC7018E79FE33B09E2734A235C96DB0EB1E22816`。更新仅作用于从未启动且证据目录仍为空的三块新盘。首轮部署因 SelfTest 随内部依赖重新编译，实际四个文件变化而触发两文件预期检查，在复制前停止；记录保留。随后按四个精确文件复核，记录为 `v4b-clean-deployment-2.json`。

完整测试必须从开发构建目录启动，以供既有用例定位 Worker，并使用规范的用户临时目录；受限沙箱不能写扫描器正常 AppData，短路径会触发身份校验，额外的工作区长路径会使既有 14,050 文件用例超过文本预算。这些未完成运行均保留日志，不计为通过。最终以 `selftest-v4b-final-results.json` 的完整结果为准。

23:54 最终完整回归 **1,940 通过、0 失败、0 跳过**，耗时约 504 秒；构建为 0 警告、0 错误。v4 串口去重、冲突、损坏与重发校验六个场景通过。这些是修复与实验脚本的前置验证，仍不代替真实样本清理、恢复和重启结果。

私有配置选择现在限定三个既定实验案例：受保护的安装前记录证明配置不存在且 Steam 干净；加载记录证明官方 VPet 加载对应插件并造成固定 chunk 与配置变化；当前扫描必须有三处各四个精确恶意源、既有配置规则和指定 chunk 语义规则，且当前完整哈希匹配。生产检测规则及配置 `IsKnownMalware=false` 不变。这允许验证实际观察到的部分 UI 链，不把单独的禁更配置升级为恶意样本。

v4 同时记录每个样本成员的哈希和文件属性，处置前后核对非处置成员，失败时也复扫。串口宿主接收改为数据到达即读取，来宾按 256 字节分段限速；继续限制帧大小、去重并拒绝损坏或身份不符的事件。

## 恢复验收条件

可信恢复介质来自感染前同版本 Steam 的 827 个官方文件，逐项匹配原始基线。恢复 ZIP SHA-256 为 `3BC0E97AAD02800310DA63A4C084194363F013B27F86A8C47289918E68B2F4A2`。样本自带 `.orig.dll`、`_local_patch_backup` 和配置备份不属于信任来源。

当前恢复脚本先停止经路径核验的实验宿主，对既有且发生变化的基线文件持有排他句柄，复核现状、备份、写入可信内容并复核结果。缺失目标或新增 `steam.cfg` 保留未解决状态。该过程是实验恢复流程，尚不是已交付的产品自动恢复功能。

验收分别核对精确隔离、无关文件保留、原三处范围复扫、Steam 文件及禁更配置恢复、系统重启复扫、Steam/VPet 再启动后不回写。AMSI、产品宿主关联、交互权限、失败中断、重新订阅等缺口单独记录，不合并为“全机安全”。

## v4 实际清理与恢复

2026-09-21 用户完成三台 LabUser 登录后，官方 VPet 分别加载 SmartPet、TianLai 和 Scratch 插件。本轮三者均改写固定 chunk 并创建 68 B 禁更配置；v3 SmartPet 的三文件 UI 链观察保留为独立历史结果，不能混入本轮文件差异。

| 案例 | 三处样本成员 | 隔离动作 | 原范围已知源复扫 | 未处置成员 | Steam 恢复 |
| --- | ---: | --- | --- | --- | --- |
| SmartPet | 42 | 12 个已知 DLL + 1 个单独确认配置，全部成功 | 0，退出码 0 | 30 个哈希不变 | 1 个 chunk 恢复，827 个基线文件匹配，配置不存在 |
| TianLai | 42 | 12 个已知 DLL + 1 个单独确认配置，全部成功 | 0，退出码 0 | 30 个哈希不变 | 同上 |
| Scratch | 180 | 12 个已知 DLL + 1 个单独确认配置，全部成功 | 0，退出码 0 | 168 个哈希不变 | 同上 |

三个隔离事件分别为 `3ce4b061-f0ee-48ca-b3c8-64bc63221b84`、`b728d147-4ec3-48a5-9ae8-c90889e99f96`、`2404a6bd-5d90-4d27-b1c9-345629027fa9`。每项均为 `Succeeded`，两轮验证均为 `NoResidual`；不能只检查总 `Success`。此次直接采集到目标 DLL 的 `ReadOnly | Archive` 属性，修复已通过真实样本场景。复扫仍为 AMSI `Partial`。

Scratch 证据传输出现字节丢失：不仅会形成非法 JSON，也会保留合法 JSON 却损坏键名或动作类型。宿主新增独立读取线程和 64 MiB 有界内存缓冲，磁盘和状态输出不阻塞读取；4 MiB 连续传输与重连校验通过，但实际串口仍出现丢字节，不能把接收程序更改称为已消除传输缺陷。

原始分段全部保留。通过诊断冷启动重发来宾在动作前后已持久化的原事件，为每个受损版本记录文件名、原文 SHA-256 和事件 ID；只接受实际收到的一条完整事件，并逐条证明同 ID 的每个受损版本均仅缺少字符。没有合并碎片或补写载荷。合法但截断的 JSON 也按精确损坏清单拒绝；未列入清单的冲突、缺少完整重发、任一损坏版本无法解释均使解析失败。8 项专项通过，见 `strict-replay-validation-2.json`；Scratch 对照见 `Scratch-v4-complete-replays-1.json`。两次诊断冷启动不计入恢复后的系统重启验收。

上述串口诊断仍有长记录缺失，后续采用下述原始文件提取核验。诊断重启不计入恢复验收；汇总以 `v4-rerun-status.json` 为准。

## v4 原始证据提取

Scratch 多次传输均出现不同位置的字节丢失，队列读取和提高读取线程优先级未解决实际串口缺陷。2026-09-21 01:27 正常关闭 Scratch 后，通过普通只读文件句柄解析已由 Hyper-V 元数据枚举的六层 VHDX 链，提取受保护 `EvidenceV4` 中四个原始 JSON 文件。没有使用 `Mount-VHD`、宿主文件系统挂载或来宾代码执行。

解析工具固定使用 Dissect hypervisor 3.21、ntfs 3.16、fve 4.6；依赖及来源哈希仅保存在工作区。读取句柄拒绝其他写入/删除，限制总读取量、单次读取量和时间；校验 VHDX/GPT 校验和、无活动 VHDX 日志、固定父盘链接和分区/卷身份。证据路径、文件所有者和 ACL 均复核，仅 SYSTEM/Administrators 可写，无重解析点。该卷有 BitLocker 元数据及既存明文密钥，解析器仅在内存中使用既有密钥；没有输出密钥、获取凭据或改变磁盘加密设置。

| 原始事件 | 字节 | SHA-256 |
| --- | ---: | --- |
| source-quarantine | 18,051 | `ADCC525DA332ADD6A059784B64C3B514BF036ECA0B59FB996029228B75560BD9` |
| steam-recovery | 49,269 | `3A2CC17FD3D49CABA43D804323861D222291C759FBF532C470E90C04F9853D85` |
| reboot-requested | 48,924 | `99B52F8CAE2CA50B827572F7C30E4BCAA7E4338D9E05C8F52B79E6A810EA5B25` |
| post-reboot-state | 48,925 | `4A517E1BBF656BD278164899D58426FBE34D0782ECBDB3E87ABE00BF508F92F6` |

第一项与此前完整串口对照事件逐字节哈希一致。提取记录为 `raw-Scratch-v4/manifest.json`，SHA-256 `4648F75A6DB306C5EF56FC80A1547C5A4117A8B55EA59A887543D6C482842866`；实际镜像读取量 1,422,024 B。解析器明确区分原始文件提取与串口捕获，固定清单和各文件哈希，不生成伪造的串口分段。前十段捕获中的 62 条损坏记录均为对应单条完整原事件的严格字节子序列，见 `Scratch-v4-complete-replays-2.json`；未合并片段或推断缺失内容。

新增原始证据校验 7 项通过：完整原件、原件缺失、原件内容修改、清单修改、串口相同副本、串口冲突，以及原件解释有记录的串口损坏。测试记录为 `raw-evidence-validation.json`。

## v4 重启与再启动验收

三台均已验证恢复后的系统启动时间发生变化，827 个 Steam 基线文件一致、禁更配置不存在，原三处范围复扫退出码 0、已知源 0。Scratch 的验收启动时间为 `2026-09-20T16:49:25.5000000Z`；后续诊断启动另列，不替代该证据。

SmartPet、TianLai 在 LabUser 登录后均已重新运行官方 Steam/VPet，未加载已隔离的恶意源模块，无模块读取失败；未出现 Steam 回写或配置再生，非处置成员哈希不变，复扫退出码 0、已知源 0。结果为 `v4-SmartPet-TianLai-acceptance.json`。两台现已保存 VM 状态并关闭接收器，封存结果及捕获哈希见 `v4-passed-cases-sealed.json`。

Scratch 于 01:57 返回再启动状态，官方 Steam 与官方 VPet 均在 LabUser 会话中运行，无已知恶意源模块和模块读取错误；827 个 Steam 文件匹配基线、配置不存在。180 个成员逐项与隔离后状态一致，其中 12 个已知源缺失、168 个其他成员哈希不变。随后原范围复扫退出码 0、已知源 0、Steam 检查发现为空；AMSI 覆盖仍为 `Partial`。

再启动长记录仍丢失了 26 B，因此收到复扫事件后正常关机，按同样的有界普通只读解析流程取出六份原始 JSON。前四份与第一次提取的哈希完全一致；新增两份如下：

| 原始事件 | 事件 ID | 字节 | SHA-256 |
| --- | --- | ---: | --- |
| relaunch-state | `32f266bf-6981-49e0-9e8b-f7736eb53c02` | 50,982 | `FB7E02E3C2F2CA102AC19536CAE53A09FFB787E2762FB0F885DB6BC2F7B2384F` |
| after-relaunch | `80d6e704-db92-4107-9f2c-c1c230d076d5` | 3,158 | `3B6CCE29DC660316EC74126F333B3248B32772F7BC16855D0FF2DC0BFD3299C6` |

最终提取清单 `raw-Scratch-v4-final/manifest.json` 的 SHA-256 为 `83E4A5EEBF4ECBD374490551E3E14BB53A6F6EB1F0BB3ABA57470D103A07AB39`，实际镜像读取量 1,536,851 B。第 1—11 段共 70 条已记录受损传输均由对应完整原件解释，最终去重事件数 39，见 `Scratch-v4-complete-replays-4.json`；加入最终原件后再次运行七项证据校验，全部通过，见 `raw-evidence-validation-final.json`。

三台限定范围验收均通过。SmartPet/TianLai 保持 Saved，Scratch 保持 Off，全部网卡断开，原恢复检查点保留，三个最终接收器已关闭并核对捕获哈希。`v4-final-sealed.json` 记录各 VM 身份、状态、检查点、捕获和主要证据文件哈希。

私有管理员驱动、固定同版本恢复介质和模拟工坊目录的边界保持不变；上述结果不代替界面/UAC、产品宿主关联、实际安装升级或联网重新订阅验收。安装未加载阶段已验证识别，但没有单独完成该状态下的清理分支；失败中断、跨账户和不同 Steam 版本等产品矩阵仍待完成。
