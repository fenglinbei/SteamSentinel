# 0.3.0 状态、原因码与显示文字

更新：2026-09-21。此设计是第 6 步英文支持的前置工作。核心状态模型、原有文字判断的替换，以及对应中英文资源已落地；完整英文界面、安装器和报告翻译按下述后续步骤推进。

## 数据流与职责

只允许以下方向：**发生的事实 → 状态和原因码 → 显示资源 → 用户文字**。禁止从翻译、错误消息、路径名称、检查名称反推出状态、成功数量或动作资格。

| 字段 | 职责 | 示例 |
|---|---|---|
| `ExecutionState` / `State` | 当前执行阶段或结果 | `Completed`、`ReviewRequired` |
| `ReasonCode` | 为什么出现这个状态 | `coverage.amsi_unavailable` |
| `MessageId` | 使用哪条显示模板 | `Scan.CompletedWithGaps` |
| `Arguments` | 模板参数，按数据处理 | 条目数、限额、目标摘要 |
| `Detail` / `ReasonDetails` | 原始系统错误、证据和补充信息 | HRESULT、路径、异常原文 |
| `CheckCode` / `Id` | 检查种类 / 本次观察的身份 | `related.host_identity` / 独立记录 ID |

`ReasonCode` 与 `MessageId` 可以同名，但职责不同。一个原因可用于多种显示模板；换文案不改原因码。参数中的花括号、命令文本或路径只作为文本显示。原始错误不承担程序分支职责。

主实现为 `Models/StatusModels.cs`、`Reporting/StatusPresentation.cs`、`StatusMessages.resx` 和 `StatusMessages.zh-Hans.resx`。当前已迁移部分的默认显示仍为简体中文；显式传入 `en-US` 可生成英文。UI 语言选择尚未接入。

同日的后续资源实施已增加 `DisplayText` 统一显示上下文与 668 组共用资源，状态呈现接入同一语言作用域；默认中文不变。风险、容器、AMSI、逐动作与复验、诊断及报告的实施和 356 项验证见 [资源实施记录](LOCALIZATION-RESOURCES-0.3.0.md)。

## 五个独立维度

不要用一个“状态”同时表示任务进度、病毒判断和清理结果。

| 维度 | 模型 | 说明 |
|---|---|---|
| 扫描执行 | 新 `ScanExecutionState` | 本次操作是否执行、结束或中断 |
| 检查覆盖 | 既有 `ScanCoverage` | 本次声明范围是否检查完整 |
| 发现与处理资格 | 既有 `FindingSeverity`、`IsKnownMalware`、`FindingDisposition`、`FindingHandlingReason` | 严重程度、证据和动作资格各自独立 |
| 处置执行 | 既有 `RemediationExecutionStatus`，新增目标汇总 `RemediationTargetState` | 单个动作与整组目标分别记录 |
| 处置后验证 | 既有 `RemediationVerificationStatus`、病例复验状态 | 未检查、已验证、待重启、残留、再次出现等 |

例如 `ExecutionState=Completed` 与 `Coverage=Partial` 可以同时成立。隔离动作执行成功而 `VerificationStatus=PendingReboot` 时，目标为 `ReviewRequired`。归档中检出已知恶意内容，不能仅因此显示主机已经感染。

### 扫描执行状态

| 稳定值 | 中文 | English | 进入条件 |
|---|---|---|---|
| `Unknown` (0) | 未记录执行状态 | Execution state unavailable | 历史记录缺字段，或显示层不能识别该值 |
| `NotStarted` (1) | 尚未开始 | Not started | 已建立操作、尚未开始 |
| `Running` (2) | 尚未结束 | In progress | 已开始，尚无最终结果 |
| `Completed` (3) | 本次扫描已完成 / 已结束，仍有未检查内容 | Scan completed / Scan finished; some content was not checked | 操作正常结束；具体文字还取决于覆盖状态 |
| `Cancelled` (4) | 扫描已取消，已保留可用结果 | Scan cancelled; available results retained | 明确取消事件 |
| `Failed` (5) | 检查失败，已保留可用结果 | Inspection failed; available results retained | 操作异常中断 |

正常路径为 `NotStarted → Running → Completed/Cancelled/Failed`。重新扫描建立新的 `ScanId`，不把历史失败记录直接改成成功。

报告合并使用保守优先级：`Failed > Cancelled > Unknown > Running > NotStarted > Completed`。未结束或未知的合并结果不设置完成时间；任一范围存在缺口仍保留缺口。分片接收过程中，即使来源已经结束，在结束时间或诊断结束帧尚未到齐时也不展示完成。最终结果仍需满足既有协议计数与结束帧校验。

`Complete` 仅表示本次范围内检查完成，`Partial` 表示存在未检查或未完整比对内容，`Skipped` 表示未执行检查。旧 `ScanCoverage` 的数值保持不变；旧记录的默认 `Complete` 不能代替新的明确执行状态。

### 处置目标汇总

| 稳定值 | 当前中文显示 | English | 含义 |
|---|---|---|---|
| `Unknown` (0) | 待核验（未记录结构化状态） | Review required (structured state unavailable) | 无法从原始机器字段确认 |
| `NotIncluded` (1) | 未处理 | Not included | 必需动作均未进入计划 |
| `PartiallyIncluded` (2) | 部分纳入 | Partially included | 只有部分必需动作进入计划 |
| `Ready` (3) | 待执行 | Ready | 已准备，执行前仍须独立核验 |
| `NotExecuted` (4) | 尚未执行 | Not executed | 相关批次尚未执行或已暂停 |
| `Failed` (5) | 未完成 | Failed | 已返回的动作存在执行失败 |
| `ReviewRequired` (6) | 需复核 | Review required | 动作成功，但验证尚未全部确认 |
| `Completed` (7) | 已完成 | Completed | 必需动作均已返回成功且验证通过 |

目标完成要求所有必需动作被纳入并返回结果，且验证状态均为 `Verified` 或 `NoResidual`。`PendingReboot`、`Unknown`、`NotChecked`、`ResidualDetected` 和 `Reappeared` 均不能计为完成；这些具体原因继续保留在逐动作的结构化验证状态中，不依赖解释文字。

完成、失败、需复核和未全部处理的数量直接按 `State` 统计。`Unknown` 算入未全部处理。准备阶段的补充说明按目标所属批次的独立 `Target` 字段关联，不再通过说明文本是否包含路径来猜测归属。界面将这些说明标为批次上下文，不把同批另一目标的说明当作当前目标的已核验事实；整体批次说明继续单独保留。

## 原因码目录 v1

下表是已落地的稳定原因码。原因码使用 ASCII，当前采用小写点分命名；验证限制为 1—96 个字符。新增代码只追加，不改名、不复用已有含义。遇到新细分原因时保留上层状态，新增明确代码；不能引入“从 Message 猜原因”的兼容分支。

| 代码 | 含义 |
|---|---|
| `legacy.unspecified` | 历史记录没有结构化原因 |
| `execution.user_cancelled` | 明确取消 |
| `execution.component_failed` | 组件异常，未归入更具体类型 |
| `execution.worker_start_failed` | 隔离组件准备、启动或握手失败 |
| `execution.allocation_failed` | 实际内存分配异常 |
| `coverage.resource_limit` | 安全预算、数量、深度、展开量或组件边界触发 |
| `coverage.system_incomplete` | 系统检查不完整 |
| `coverage.trust_proxy_incomplete` | 代理或证书检查不完整 |
| `coverage.content_not_started` | 后续内容检查未执行 |
| `coverage.workshop_selection` | 只选择部分工坊范围 |
| `coverage.read_budget` | 单文件或累计读取预算不足 |
| `coverage.engine_size_limit` | 字符串或 AMSI 正文检查大小限制 |
| `coverage.quick_media_structure` | 视频做了结构检查，未进行整文件比对 |
| `coverage.quick_content_not_hashed` | 快速检查没有完整哈希 |
| `coverage.archive_not_expanded` | 压缩内容未展开 |
| `coverage.archive_encrypted` | 加密内容未解开 |
| `coverage.amsi_unavailable` | 本机反恶意软件辅助检查不可用 |
| `coverage.read_incomplete` | 其他读取或范围缺口 |
| `coverage.unsafe_path` | 路径不能安全读取 |
| `coverage.access_denied` | 权限不足 |
| `remediation.plan_ready` | 目标已纳入计划 |
| `remediation.actions_not_included` | 部分必需动作未纳入 |
| `remediation.evidence_unavailable` | 缺证据或关联核验未完成 |
| `remediation.target_unavailable` | 目标不存在、不可读或无法重新核验 |
| `remediation.action_failed` | 动作执行失败 |
| `remediation.waiting_batches` | 等待后续批次 |
| `remediation.verification_incomplete` | 处置后验证未确认；细分见验证状态 |
| `remediation.actions_verified` | 所选动作及目标验证完成 |
| `remediation.plan_expired` | 计划过期，后续动作停止 |
| `remediation.batch_incomplete` | 本批有失败、残留或未确认结果 |
| `remediation.execution_interrupted` | 执行中断，后续批次未执行 |

补查按钮仅根据明确支持补查的原因码和安全目标路径启用；未知原因不给予快捷补查资格。按钮不改变既有扫描预算或处置权限。旧 `RuleId` 若具有明确的机器语义，可通过显式映射得到原因码；自由文本永不用于这一映射。

后台异常通过 `WorkerMessage.ReasonCode` 传递；兼容旧 Worker 时只接受结构化的 `Diagnostics.FailureType`，不搜索错误原文中的异常名。真实启动失败、预算触发与内存分配失败应给出不同建议。

关联诊断的 `CheckCode` 表示检查种类，如 `related.source_target_limit`、`related.host_identity`、`related.total_check_limit`。`Id` 表示独立观察。限额标识按 `CheckCode` 判断，合并按观察 ID 保留身份；未绑定身份的独立事件保留各自记录，不因中文名称或相似错误文字而合并。原有记录数量和单字段限制继续执行。

## 序列化与旧数据

扫描报告新增 `StatusSchemaVersion=1`，同时保存执行状态和原因码。示例为结构说明，省略其他报告字段：

```json
{
  "StatusSchemaVersion": 1,
  "ExecutionState": "Completed",
  "ExecutionReasonCode": null,
  "Coverage": "Partial",
  "CoverageNotices": [
    {
      "ReasonCode": "coverage.amsi_unavailable",
      "Detail": "原始提供程序诊断与 HRESULT",
      "Target": "原始检查目标",
      "Message": null
    }
  ]
}
```

- 新写入的执行状态及处置目标状态保存机器字段，计算出的中文 `ExecutionStatus`、`Status`、`Reason` 不作为新状态协议。
- 旧 JSON 的同名文本通过 `LegacyExecutionStatus`、`LegacyStatus`、`LegacyReason` 别名保留。缺少新状态时保持 `Unknown`；即使存在完成时间或“已完成”文字，也不补造成功状态。原文仍可从 JSON 读取，Markdown 保留扫描原始状态说明。
- 旧覆盖自由文本继续显示为一般范围说明；不会依据“上限”“AMSI”“取消”等字样设置分类。明确的旧规则 ID 可兼容映射。
- 未知但格式有效的原因码保留，显示通用说明；未知消息 ID 回退为含该 ID 的可读提示，不授予操作资格。
- 非法代码、越界参数、无效状态值或不支持的扫描状态 schema 在 Worker 分片边界被拒绝，且拒绝前不提交该批发现。未知枚举字符串按现有 JSON 枚举解析规则拒绝，不静默改成成功。
- 历史隔离记录及受保护结果的既有 schema 和 Broker 验证逻辑不因显示模型升级而改写。界面清理空事件的前置判断额外要求明确的 `Completed`，仍不是 Broker 的处置授权证明。

新增消息限制为最多 8 个参数，每个最多 4096 字符；覆盖说明正文最多 65536 字符、目标最多 32768 字符，并计入原有报告总记录数与文本预算。新覆盖说明采用有界批次传递，最终帧重放更新过的说明，解决 AMSI 汇总在扫描中递增的情形。

`CoverageNotes` 等历史自由文本可继续用于展示和展示去重；不得再作为执行结果、原因分类或操作资格的输入。`StatusMessage` 只控制显示，不能承载可执行模板或动作。

## 后续实施顺序

1. **状态基础（本次）**：替换扫描取消判断、目标计数、覆盖原因分类、Worker 错误判断及关联诊断名称判断；建立共享资源和兼容读取测试。
2. **资源迁移**：沿五个维度迁移剩余风险解释、容器阶段、AMSI HRESULT 外层说明、逐动作结果和验证结果。保留既有枚举，不另造一套互相冲突的状态。新增错误由发生点写原因码，OS 原始错误单独保留。
3. **语言设置与 UI**：接入自动/简体中文/English，持久化选择；绑定状态和原因模板，补全页面、弹窗、密码流程及英文长度布局验收。首版允许重启应用生效。
4. **导出、管理员边界和安装**：Markdown 按所选语言渲染，JSON 机器字段保持稳定；管理员窗口只接收白名单语言值。将资源卫星 DLL 纳入安装、升级、哈希及签名清单，补双语帮助。
5. **联合验收**：同一输入在中英文下比较规则命中、哈希、风险/覆盖状态、动作集合和权限拒绝结果，允许的差异仅为显示资源、数字日期格式和显示语言记录。新版构建需重新经过既有 Preview/RC 门槛。

第 5 步三个感染克隆的证据仍对应原封存构建。本次改动不能借用那份二进制的验收结果宣称新包已通过感染清理、安装或双语界面验收。

## 验证记录

- 最终 `--status-model-tests` 定向回归：227 项通过、0 失败、0 跳过，含中英一致性、旧 JSON 往返、未知代码、消息参数、分片原子拒绝、AMSI 汇总、处置计数、过期计划及关联诊断。结果：`work/v03-step6-20260921/focused-final-v2/results.json`。
- Release 构建：0 警告、0 错误。
- 31 个原因码均已列入本目录；67 组中英文资源键和参数占位符一致。
- 本机完整回归首轮：1962 项通过、14 项失败、0 跳过。其中 4 项依赖原有文字字段的旧测试数据已迁移，并通过受影响专项与 UI 对照复测。此后仅做针对性复测，没有把首轮完整回归记录改写为全通过。
- 新旧构建的独立布局对照均为 324 项通过、10 项失败，失败集合完全相同；见 `ui-comparison.json`。这些布局问题在当前环境的封存旧版上同样出现，已纳入后续双语 UI 验收，本次不宣称完整回归全绿。
- 两次沙箱执行分别遇到 Worker 自有目录/无害归档临时目录权限限制，原始失败记录保留；最终相关测试在本机自检环境通过。完整记录索引见工作目录 `work/v03-step6-20260921/STATUS-VALIDATION.md`。
