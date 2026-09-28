# SteamSentinel 0.3.0 发布状态与验收索引

更新日期：2026-09-28。[English](RELEASE-0.3.0.en.md)

产品 **0.3.0** 已于 2026-09-28 公开发布为 [v0.3.0-preview.3 自签名 Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.3)。本页记录其发行身份和验收范围。规则版本为 `2026.09.28.1`；本轮完整重编译产品及安装器。不同构建、阶段与测试助手的结果分别记录，旧记录不改写为新包验收。

## 下载与身份

| 项目 | 本轮发行身份 |
| --- | --- |
| 发布标签 | `v0.3.0-preview.3` |
| 产品版本 / 平台 | `0.3.0` / Windows x64，安装器最低目标 Windows 10 build 19041 |
| 规则版本 / 自包含运行时 | `2026.09.28.1` / `.NET 10.0.12` |
| 安装包 | `SteamSentinel-0.3.0-preview.3-selfsigned-setup.exe` |
| 安装包 SHA-256 | `33AE8B1B9A1C5C2E8B82F92210686FE9E525BF59415C89FD03F53E5C1DEA140B` |
| 干净构建源码提交 | `67e507b744a88e072707ae3c6d2ebdf34f3e7429` |
| 构建源码树 | `7f533a585afa0cc08f81dd73dec4e27ffc530964` |
| 产品构建身份 | `0.3.0+67e507b744a88e072707ae3c6d2ebdf34f3e7429.preview` |
| 载荷 / 二进制 ZIP / 源码 ZIP | 清单 535 项 / 536 个文件（含清单）/ 410 个文件 |
| 签名状态 | `SELF-SIGNED-PREVIEW`，无公共受信任证书链及时间戳 |

下载以发行页实际可见的附件为准。使用完整安装包，并核对同页的 [SHA-256 清单](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/SteamSentinel-0.3.0-preview.3-selfsigned-RELEASE-SHA256.txt)、[PUBLICATION-IDENTITY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/PUBLICATION-IDENTITY.json) 和 [RELEASE-METADATA.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/RELEASE-METADATA.json)。版本号相同不代表构建相同；后续主分支文档更新不改变上述产品源码提交与构建身份。

证书为 `CN=fenglinbei`，SHA-1 指纹 `3395882D18D66EFA1545C1FE6DD867EB004176D1`，有效期至 `2027-09-04 10:00:58 UTC`。Windows 可能提示发布者不受信任；`SIGNER.cer` 仅含公钥，不自动修改系统信任库。安装器及七个产品文件已完成签名完整性核验；安装后的卸载器与 VM 验收分别见下表。详情见 `SIGNING.txt` 和 [签名说明](SIGNING.md)。

## 规则修正 3

- 通用词语共现改为 Medium/40、仅供复核，不再授予文件隔离或宿主终止资格。MSI 通用静态声明、快捷方式及运行历史中的同类弱证据遵守相同边界；仅由弱文件观察得到的关联保持诊断性质。
- `.node` 与有效 Windows PE 原生模块兼容，内容与哈希仍检查；仅匹配历史落地路径时为 Low/20 观察，不以文件名或目录名决定恶意身份。
- 精确恶意哈希、专用强规则、VPet 有界家族识别和独立配置证据保留各自资格。新的精确恶意哈希证据使用独立规则身份，不恢复退役弱规则的授权。
- 证据仅保留有界固定词、编码及解码窗口位置，不复制任意邻近原文，不据此证明执行顺序。扫描不会运行脚本、快捷方式或提取程序来验证这些词语。
- 旧报告和病例保留原文、分数及当时结果；界面和新计划入口拒绝退役弱规则，并保留未纳入原因。请使用本轮版本重新扫描原范围；升级或复扫不自动撤销旧处置。

“仅供复核”不表示已经证明安全。通用文件隔离仍不在管理员 Broker 内对每条扫描结论作独立恶意性重判；本轮加强的是界面、关联与新计划资格判断，未引入高权限归档解析或完整报告防伪证明。见[修正原则与边界](FALSE-POSITIVE-CORRECTION-0.3.0.md)。

## 0.3.0 的产品能力

- 检查已分析的 SmartPet、天籁之音、刮刮乐原始包、核心组件及已验证派生载荷，保留组件关系、Steam HTML／CSS／JS 与客服路由的逐文件证据，支持 ZIP 中文成员名称。
- 提供简体中文和 English，按用户保存显示语言并于下次启动生效；Markdown 与记录包可单独选择导出语言，JSON 机器值和原始证据不随显示语言改变。
- 资源预检与按次提额不越过权限、路径、身份或格式条件。普通文本和脚本按实际 CPU、内存及预算使用有界 1／2／4 路并行，复杂容器保持原顺序；不宣称已测得加速倍数。
- 保留精确处置预览、未纳入原因、文件占用与锁定句柄身份检查，以及符合条件的只读恶意源隔离和拒绝覆盖式回滚。
- 保留修订 2 的合法短路径安装修复、精确旧图标迁移及路径诊断；已验真 0.2.0 来源仅在固定空目录满足条件时自动收紧权限，已有数据和未知来源继续保留。

使用步骤见 [README](../README.md) 与 [English quick start](QUICKSTART.en.md)。

## 本轮验收及原始失败记录

详细结果以 [ACCEPTANCE-SUMMARY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/ACCEPTANCE-SUMMARY.json) 的实际发行附件为准。独立运行的通过数不相加为一次完整自测。

| 证据层 | 已核验结果 | 适用边界 |
| --- | --- | --- |
| 干净源码完整构建 | 原生 apphost、自包含 `.NET 10.0.12` 完整自测 2,469 通过、0 失败、0 跳过 | 本轮重新运行，绑定上述 clean commit 和 Preview 构建身份 |
| 同提交 Windows CI | [run 36421041587](https://github.com/fenglinbei/SteamSentinel/actions/runs/36421041587)：2,469 通过、0 失败、0 跳过；构建与格式检查通过 | 独立 CI 运行，构建身份后缀为 `.ci`；不与原生通过数相加 |
| 本轮安装源码专项 | 维护 56 项、状态迁移 43 项，均 0 失败、0 跳过 | 新运行的安装专项，不能替代最终安装包 VM 验收 |
| 签名及包结构 | 安装器、七个产品文件签名完整性通过；载荷清单 535 项，二进制 ZIP 536 个文件，源码 ZIP 410 个文件 | 自签名，未取得公共信任或时间戳 |
| 正式签名 Core 历史资格回放 | 3 份报告的 3 项直接旧弱规则全部不可处置；独立原有配置项 1/1 保留；原 ZIP 3/3 未改写 | 只读旧 JSON，不读取报告目标、不执行程序、不生成处置计划；公开只发布汇总计数 |
| 原 Windows 10／11 普通用户助手 | 各 3/4，通过的三项扫描／导出检查保留；取消项未通过 | 助手按过时 Stage 显示文字判断，未触发取消；原失败不改写为 4/4 |
| 最终包 Windows 10／11 基础验收 | **Windows 10 build 19045、Windows 11 build 26200 均完成升级、同版重装、535 项载荷与原记录／权限保留检查，以及中英文启动探针** | 原三项扫描／导出与独立取消补验分别列明；启动探针不代替新一轮目视 GUI 验收 |
| 正式包误报专项 | Windows 10／11 各 164 通过、0 失败、0 跳过 | 绑定最终签名产品，保留强规则与弱证据资格回归 |
| 独立取消补验 | **两机各在简体中文和英文运行一次，均实际触发并完成取消，无新增 Worker 临时目录残留** | 以稳定阶段 ID 触发，逐机列简体中文及英文结果，不替换旧助手原记录 |
| 原始恶意 ZIP 静态语料 | **三份原始 ZIP 均完成静态扫描，全部 15 条预期强规则及处置资格保留；覆盖为 Complete／Partial／Complete，天籁未解释依赖尾部继续为 Partial** | 仅声明实际完成的扫描、检测与覆盖，不作为重新感染、隔离或恢复验收 |
| 最终包重启复核 | **两机各重启一次，新启动时间、535 项载荷、原记录与权限及卸载器身份复核通过** | 按实际系统、构建身份、语言和复核范围列结果 |

## 历史安装修复与验收

[preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2) 已修复 `ADMINI~1` 等合法 Windows 短名称触发的 `Code=UnsafePath; Path=; Mode=Preflight`，通过实际句柄解析和固定父目录保留对重解析、硬链接及不可信写权限的拒绝。早期 `Assets\App.ico`、`Assets\App.png` 仅在大小与 SHA-256 同时匹配时退役；未知或改动文件保留。遇到旧安装器的短路径问题，应退出普通及管理员窗口后使用本轮完整安装包，无需手动删除文件或放宽权限。详见[安装升级规则](INSTALLER-UPGRADE-0.3.0.md)。

preview.2 的七个产品二进制与 preview.1 一致，当时保留 **2,358 项**完整回归基线，未重跑产品完整自测；新增源码维护 56／状态 43 项及 Windows 10／11 安装流程、各 531 个载荷文件和普通用户／重启核验。其源码快照为 `5878b6139caaf7cab90c647eb92c9c5d8a6febc6`，程序保留原 dirty Preview 身份。这些是历史事实，本轮 2,469 项全新完整自测和 clean build 不沿用该身份。原附件仍见 [preview.2 验收摘要](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/ACCEPTANCE-SUMMARY.json)。

候选09及 preview.1 的 Windows 10 GUI 152 项、Windows 11 GUI 35 项、原始恶意 ZIP 静态检查 89 项、Scratch GUI／记录 208 项、安装向导证据 34 项继续绑定各自原候选或阶段。更早的感染、隔离、同版本 Steam 恢复及重启记录也保留原身份，不能改称本轮完成同样的感染恢复全流程复测。本机实际早期安装的只读预检、VM 旧布局夹具和完整旧构建重装也不得混为同一证据。

## 保留范围

- 基础扫描不调用 AMSI，缺少该可选增强项不会单独导致不完整；真实读取、密码、格式、权限与资源缺口仍显示。历史报告不重写。
- ISO／DVD 扫描不在承诺范围。原始归档静态检查与历史 JSON 资格回放分别计数；不宣称三份旧报告提到的原 DLL 已逐份安全验真。天籁两段未解释依赖尾部继续保留 Partial。
- 物理跨屏和 AMSI 提供程序健康排查暂停。旧版有条件迁移提示未触发目视检查，继续保留已接受缺口；迁移行为有独立测试。
- 动作完成与精确目标复核不证明整机无感染。精确证书／代理规则及真实修复受[第三批范围](EXACT-REMEDIATION-PHASE3.md)约束，不仅凭名称删除配置。
- 普通导出不包含恶意载荷或归档密码。旧病例不能直接重放为管理员授权；活动隔离记录不能永久删除，只有核验为空且全部已回滚的事件可清理。

## 来源

- 本轮发行附件：[中英文发布说明](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/RELEASE-NOTES.md)，以及上述身份和验收附件。
- [preview.1](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.1)、[preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2)、[变更日志](../CHANGELOG.md)、[实施规划](PLAN-0.3.0.md)、[早期联合验收](JOINT-ACCEPTANCE-0.3.0.md)、[第三方声明](../THIRD-PARTY-NOTICES.md)。历史“开发中”“待验收”等表述应按日期和构建身份阅读。
