# SteamSentinel 0.3.0 发布状态与验收索引

更新日期：2026-09-28。[English](RELEASE-0.3.0.en.md)

产品版本 **0.3.0** 当前已发布为 [v0.3.0-preview.2 自签名预发布版](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2)，安装修订号为 **2**。本页汇总当前发行身份与验收范围；较早规划、实施记录和源码快照保留其成文时状态。GitHub 的 Pre-release 标记仍然有效，不表示完成公开受信任签名发行。

## 下载与身份

| 项目 | 当前发行身份 |
| --- | --- |
| 发布标签 | `v0.3.0-preview.2` |
| 产品版本 / 平台 | `0.3.0` / Windows x64，安装器最低目标 Windows 10 build 19041 |
| 自包含运行时 | `.NET 10.0.12` |
| 安装包 | `SteamSentinel-0.3.0-preview.2-selfsigned-setup.exe` |
| 安装包 SHA-256 | `0A3DC1284BFC029E454316B89DC08A9216CBAF8411E3608C5EE85A51C9BFD2D7` |
| 标签源码快照提交 | `5878b6139caaf7cab90c647eb92c9c5d8a6febc6` |
| 标签源码树 | `1f9a0d2125dff8be2c72c8e8a2c16bd6bd271fd2` |
| 产品原构建身份 | `0.3.0+e645c27207d406721a67e3d13ae0ec2f7e43449e.dirty.preview.7639ef7cb1eb` |
| 产品原源码树 | `7639ef7cb1eb885661d054321279879d7058c2ae` |
| 签名状态 | `SELF-SIGNED-PREVIEW`，无公共受信任证书链及时间戳 |

从发行页下载完整安装包，并核对同页的 [SHA-256 清单](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/SteamSentinel-0.3.0-preview.2-selfsigned-RELEASE-SHA256.txt)、[PUBLICATION-IDENTITY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/PUBLICATION-IDENTITY.json) 和 [RELEASE-METADATA.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-METADATA.json)。版本号相同不代表安装修订或构建来源相同。

证书为 `CN=fenglinbei`，SHA-1 指纹 `3395882D18D66EFA1545C1FE6DD867EB004176D1`，有效期至 `2027-09-04 10:00:58 UTC`。Windows 可能提示发布者不受信任；`SIGNER.cer` 仅含公钥，本次发布没有修改系统信任库。签名详情见发行附件 `SIGNING.txt` 和 [签名说明](SIGNING.md)。

七个产品二进制与 preview.1 逐字节一致，产品代码未重新编译。载荷中的 529 个文件不变，仅安装迁移文档及 `VERSION.txt` 更新；安装器从修复源码重新编译并签名。源码 ZIP 的 400 个文件已逐份按 Git 行尾规范化与标签树核对。程序保留原 dirty Preview 构建身份，不宣称从后来补建的源码快照提交重新构建。后续主分支文档同步也不改变既有发行文件的哈希、标签或验收身份。

## 修订 2 的安装修复

- 修复合法 Windows 短名称（例如 `ADMINI~1`）触发的 `Code=UnsafePath; Path=; Mode=Preflight`。通过实际句柄解析并固定父目录，保留对重解析跳转、硬链接和不可信写权限的拒绝。
- 新增早期 0.3.0 的 `Assets\App.ico`、`Assets\App.png` 精确迁移规则，大小及 SHA-256 必须同时匹配；修改过或未知的文件仍保留并阻止升级。
- 路径错误记录用途、阶段、输入和实际路径，避免仅有空 `Path`。

遇到旧包的上述错误时，退出普通及管理员程序窗口后运行修订 2 的完整安装包，无需手动删除旧文件或放宽安装目录权限。旧版迁移资格和记录保留规则见 [安装升级说明](INSTALLER-UPGRADE-0.3.0.md)。

## 0.3.0 的产品能力

- 扩展本次 SmartPet、天籁之音与刮刮乐变体的原始包、核心组件、已验证派生载荷及组件关系检测，修复 ZIP 中文成员名称处理；Steam HTML、CSS、JS 及客服路由检查保留逐文件证据。
- 提供简体中文和 English，按用户保存显示语言、下次启动生效；Markdown 和记录包可单独选择导出语言。稳定状态和原因码与文字分离，原始证据及旧自由文本保留原文，JSON 机器值不因显示语言变化。
- 扫描前预检资源，额度受限时可保持、停止或提高后继续；默认仅影响本次扫描。普通文本与脚本支持受整轮预算约束的 1／2／4 路并行，复杂容器继续按原顺序处理。
- 改善小窗口及缩放布局，处置预览显示精确动作和未纳入原因；修复已持有所需权限时只读恶意源的隔离，保留文件身份、占用和管理员计划核验。
- 改进已验真 0.2.0 来源升级：仅四个固定空状态目录满足条件时自动收紧写权限，并保留受保护的安装进度。已有数据、未知来源或不符合条件的权限继续保留并解释原因。

使用步骤见 [README](../README.md) 和 [English quick start](QUICKSTART.en.md)。

## 验收证据及适用范围

详细结果以当前发行附件 [ACCEPTANCE-SUMMARY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/ACCEPTANCE-SUMMARY.json) 为准。不同构建与阶段的测试不能相加为一次完整复测。

| 证据层 | 已完成范围 | 适用边界 |
| --- | --- | --- |
| 修订 2 归档源码专项 | 安装维护 56 项、状态迁移 43 项；均零失败、零跳过 | 本修订新运行的安装专项 |
| 修订 2 最终签名包 | Windows 10 build 19045、Windows 11 build 26200 各通过 56 项维护专项；旧包复现短路径错误后，新包短路径升级及普通路径重装通过，覆盖中英文安装执行 | 两机各核对 531 个载荷文件、三份精确旧资源夹具退役、原记录与权限保留；各 4 项普通用户扫描／导出／取消及重启复核通过 |
| 实际早期安装 | 修复后生产只读预检通过，文件与 ACL 不变 | 没有自动升级本机；虚拟机旧布局夹具与实际旧安装只读证据分别记录，不宣称完整早期构建重装 |
| 产品完整回归基线 | 2,358 项通过，零失败、零跳过 | 七个产品二进制与 preview.1 一致；本安装修订没有重跑完整产品回归 |
| 候选09及 preview.1 | 已记录 Windows 10 GUI 152 项、Windows 11 GUI 35 项、原始恶意 ZIP 静态检查 89 项、Scratch GUI 与记录 208 项、安装向导证据 34 项，失败均为零 | 各自仍绑定原候选／阶段；preview.1 签名后另有安装与普通用户流程证据 |
| 更早候选 | 感染、隔离、同版本 Steam 恢复和重启记录保留 | 不改称候选09、preview.1 或修订 2 完成同样的全流程感染恢复复测 |

安装器、七个产品文件及两台系统的实际卸载器均完成签名核验。历史测试助手问题和修正仍保留在验收摘要中；只把最终成功执行的限定流程记为通过。

## 保留范围

- 基础扫描不调用 AMSI，缺少该可选增强项不会单独导致不完整；真实读取、密码、格式、权限或资源缺口继续显示。旧报告不会被重写。
- 不承诺 ISO／DVD 扫描；本轮三份原始恶意 ZIP 使用逐份核对哈希的 NTFS 副本。天籁两段未解释依赖尾部继续保留 Partial。
- 跨物理显示器测试和 AMSI 提供程序健康排查暂停。旧版有条件迁移提示没有触发目视检查，这是已接受的保留项；迁移行为有独立测试。
- 提高额度不能越过权限、路径、身份或格式条件，也不会自动授权处置。动作成功或目标复核未发现残留只适用于精确目标，不证明整台电脑无感染。
- 不声称已测得并行加速倍数。精确证书／代理恶意配置规则及其真实修复验收仍受 [第三批交付范围](EXACT-REMEDIATION-PHASE3.md) 约束，不能仅凭名称自动删除配置。
- 普通导出不包含恶意载荷或压缩包密码。保存的病例不能直接重放为管理员授权；活动隔离记录不能永久删除，只有核验为空且全部已回滚的事件可清理。

## 公开来源与历史记录

- 当前发行的 [中文说明](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-NOTES.zh-CN.md) / [英文说明](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-NOTES.en.md)，以及上文的身份和验收附件。
- [preview.1 发行页](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.1)：首次自签名发布、候选09及其历史证据关系。
- [变更日志](../CHANGELOG.md)、[实施规划](PLAN-0.3.0.md)、[早期联合验收记录](JOINT-ACCEPTANCE-0.3.0.md)、[第三方声明](../THIRD-PARTY-NOTICES.md)。历史文档中的“开发中”“待验收”“未制作安装包”应按其日期与构建身份阅读。
