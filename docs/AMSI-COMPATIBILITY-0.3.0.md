# 0.3.0：受限 Worker 的 AMSI 兼容修复

**当前决定（2026-09-26）优先于下文历史规则：** 按用户要求，0.3.0 暂停系统 AMSI 增强入口和实际调用，不因该增强项未参与而把基础扫描标为 `Partial`。新报告记录实际关闭设置；历史 AMSI 失败、原始设置和 Partial 结果不改。真实读取或解析缺口仍保留，Norton 修复与真实 AMSI 健康不再作为基础验收门禁。源码构建 `0.3.0+local.basic-final2-20260926` 的基础验收已完成，详见[本轮记录](C:/Users/Administrator/Desktop/资料/假红信/work/v03-basic-acceptance-20260926/RESULT.md)；没有替换旧安装候选或冻结新包。下文继续保留 2026-09-23 的独立修复及实际引擎验收证据，不据此宣称当前又启用了增强项。

2026-09-23，Scratch 断网实验机已定位并验证本次初始化故障：Worker 的环境变量白名单缺少 `SystemDrive`。该环境下 Microsoft Defender 的 AMSI 初始化返回 `0x80070103`，没有提交扫描字节。增加从 Windows 目录推导的 `SystemDrive` 后，保留原有 Low 权限和 Job 限制即可完成扫描。

这是源码修复及独立验证构建的结果。已安装 V3、已有安装器、预览包及历史 Partial 报告均保留；尚未生成包含此修复的新安装包，也未冻结 RC。

## 实测边界

- Scratch：Windows 11 Enterprise Evaluation，10.0.26200，X64；Defender 平台 `4.18.26080.4`，引擎 `1.1.26080.3`，签名 `1.459.292.0`。
- 父进程使用普通 `LabUser`，Medium；扫描子进程为 Low，未获得管理员权限。
- 输入仅为固定的 45 B 无害文本和官方正常 DemoClock 插件的两个 DLL。DLL 大小分别为 183,320 B 和 712,216 B。未执行 DLL 或恶意样本。
- 通过只读光盘输入工具、单向串口取回证据；实验网卡保持断开。

## 定位证据

| 对照 | 结果 |
| --- | --- |
| 普通 Medium、原有环境 | 初始化、会话、扫描均成功 |
| Low、原有环境 | 成功 |
| 原受限令牌、默认对象权限、完整 Job，保留原环境 | 成功 |
| Medium、Worker 精简环境 | 初始化失败，`0x80070103`，提交 0 B |
| 原安装 V3 的实际 Worker | 同样失败；正常插件报告为 Partial |
| 精简环境逐项补回变量，共 25 组 | 仅补回 `SystemDrive` 的一组成功；其余 24 组失败 |
| 从 Windows 目录推导 `SystemDrive`，三次重复 | 全部成功；两次省略变量的对照仍失败 |

第一轮共 12 组。第二轮排除了本次故障通过单独补回 `ALLUSERSPROFILE`、架构变量、用户变量、完整 PATH 或调用方 TEMP 即可解决的可能性。成功进程的调用后模块快照包含 `MpOav.dll` / `MPCLIENT.DLL`；失败快照只有 `amsi.dll`。快照不能证明提供程序在此前任何时刻都未被短暂加载。

这些结果说明该版本、该提供程序的可复现故障由环境变量缺项触发。尚未追踪提供程序内部具体函数，不将本次现象推广为所有 AMSI 提供程序的要求。

## 源码改动

1. `SteamSentinel.App/Native/RestrictedProcess.cs`：在固定白名单中增加 `SystemDrive`，由 `Environment.SpecialFolder.Windows` 的路径根生成。未硬编码 `C:`，未继承调用方值，未改动 Low 令牌、默认对象权限、Job、句柄列表、PATH 或临时目录约束。
2. `SteamSentinel.SelfTest/V018Tests.cs`：新增实际子进程回归。调用方改写 `SystemDrive` 并设置一个白名单外标记，验证子进程得到系统盘、没有继承标记，且保持 Low、系统 PATH、私有 TEMP/TMP，正常退出。4 项通过。
3. `SteamSentinel.SelfTest/V030Diagnostics.cs`：区分诊断执行完成与 AMSI 实际通过。无害输入须取得扫描返回值并提交完整字节，两个 DLL 的 Worker 观察须为 Complete、Low、成功的初始化/会话/ScanBuffer；不可再以“Worker 跑完”代表 AMSI 成功。

状态码、原因码、结构化消息和双语资源契约未变化。AMSI 在其他环境中不可用时，原有失败诊断与 Partial 规则继续适用。

## 实际生产客户端及 Worker 复验

第三轮从只读介质加载修复后的实际 `ArchiveWorkerClient`，调用实际 Worker。未用私有矩阵启动器替代这三次生产调用。

| 调用方文化 | 调用方 SystemDrive | 正常插件结果 | AMSI |
| --- | --- | --- | --- |
| en-US | 缺失 | 8 文件，919,942 B，无已知恶意或可处置发现，Complete | 两 DLL 完整提交，Low，HRESULT 均为 0 |
| zh-Hans | `caller-supplied-value` | 同上 | 同上 |
| en-US | `Q:` | 同上 | 同上 |

每次 AMSI 实际提交 895,536 B；文本对照在独立矩阵中另提交 45 B。摘要分别记录已知恶意及可处置发现数量，未记录全部级别的发现总数，不据此声明总发现数为零。Complete 仅描述这次正常插件的所选范围，不代表整机安全。以上文化设置验证后台调用结果，不能代替新安装包的双语界面验收。

验证构建为 `0.3.0+unattributed.local`，明确属于私有验证产物。实际 App SHA-256 为 `DB6E4F927D60B649CD5DDB6B3D1E9893990DE9E84596F01FA1BF54A85F29142D`，共享的运行时 Core 为 `749B5A1CD300935202D993A43665C5B100A5E38D12693A474EFBD89177A22D87`，Worker EXE 为 `43454A46139B8C92EC7CC25119DE3788F94F9CF48D79907FC88744D4DD599D8B`。普通构建的 App 编译引用 Core 与 win-x64 发布 Core 的二进制哈希不同，版本及源码 API 一致；实际探针与 Worker 使用同一份已核对哈希的发布 Core。后续正式候选仍须完整打包并按候选身份复验。

## 证据和验收限制

工作目录为 `work/v03-amsi-20260923`（相对项目外层工作区）。

- `verification-amsi-20260923.json`：42 项证据核验通过；接受状态为 `passedAfterIndependentRecordVerification`。
- `originals-r1` / `originals-r2`：安装版失败及隔离变量的原始事件。
- `originals-r3`：第三轮准备事件及原收集器失败。探针已生成结果，但收集器误保留旧的 25 行及 `candidateTree` 校验，未输出正常完成事件。
- `originals-r3c`：补充收集完整结果，保留来宾原文件 SHA-256。原文件仍保存在来宾；未重新扫描，未推断已注销任务的退出码。
- 补充收集器对哈希表和反序列化对象使用 `Sort-Object path`，又误报文件变化。全部 23 个机器记录、8 个安装文件、8 个正常插件文件按路径逐项核对后，长度、SHA-256、属性完全一致。`collector-ordering-reproduction.json` 在 PowerShell 5.1 重现误报，并证明显式 `Sort-Object { $_.path }` 的比较一致。
- 两次收集器失败、首次证据核验失败以及原 `observedStateUnchanged=false` 均保留；最终结论依赖完整记录的独立核验，不覆盖原字段或原事件。四个串口接收器均已关闭，无损坏帧、缺块或残帧。
- `repair-binding-r3.json` 和 `amsi-fix-review.diff` 记录三处源码改动前后身份及可审阅差异。

源码构建为 0 警告、0 错误。完整回归为 **2,205 通过、10 失败、0 跳过**，不能记为全绿。10 项均为当前 150% DPI 下的既有界面布局检查；使用原 V3 App/Core/Broker 的独立中文布局对照同样为 347 通过、相同 10 项失败。此前通过的布局记录为 100% DPI。此对照排除了这三处 AMSI 改动作为这组失败的必要条件，但未区分每项是界面缺陷还是布局断言容差问题。

## 下一阶段

1. 处理 150% DPI 下的布局及断言问题，再补约定的 DPI 和 Windows 版本矩阵。
2. 生成包含此修复的新候选，执行实际安装后的普通用户/管理员 AMSI 复验；保留不可用提供程序的错误/Partial 验收。
3. 在隔离机补提供程序可识别的官方无害阳性测试、目标 Defender/系统版本组合，以及需要支持的第三方提供程序。当前正常样本成功不等于完成阳性检测验收。
4. 根据候选实际改动补双语联合验收，再与用户沟通冻结候选身份、支持范围和已知限制。

English: The sanitized worker environment omitted `SystemDrive`. Deriving it from the Windows directory restored Defender AMSI scanning under the existing Low token and Job restrictions in this lab. Three real production-client/Worker runs succeeded with a missing or poisoned caller value. This is a source fix and private validation build, not a release package; the ten reproduced 150% DPI layout failures remain open.
