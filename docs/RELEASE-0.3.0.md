# SteamSentinel 0.3.0 处置修订 4

更新：2026-09-29。[English](RELEASE-0.3.0.en.md)

本轮为 [v0.3.0-preview.4 自签名 Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.4)，产品版本仍为 **0.3.0**，规则版本仍为 `2026.09.28.1`。重点降低处置操作的使用与理解成本，修复“能选中威胁，但预览处置按钮一直不可用”。

## 安装与使用

关闭普通及管理员红信窗口，使用发行页的 `SteamSentinel-0.3.0-preview.4-selfsigned-setup.exe` 完整升级，再重新扫描原目录。无需删除病例或手改配置。界面会自动检查旧操作；需要补充操作时，在按钮附近显示原因，并提供“检查并继续”“重新扫描”或“查看记录”。

旧操作确认已结束后，不再仅因旧结果未知而一直阻断新的处置。历史未知结果仍保留，不会显示为成功，也不会重新执行旧计划。实际处置范围、路径和哈希核验、强证据条件保持不变。详见[处置恢复设计](REMEDIATION-RECOVERY-0.3.0.md)。

## 发行身份

| 项目 | 本修订 |
| --- | --- |
| 标签 / 产品版本 | `v0.3.0-preview.4` / `0.3.0` |
| 平台 / 自包含运行时 | Windows x64；最低 Windows 10 build 19041 / `.NET 10.0.12` |
| 规则版本 | `2026.09.28.1` |
| 安装包、源码提交、源码树及 SHA-256 | 同页 `PUBLICATION-IDENTITY.json`、`RELEASE-METADATA.json` 和 `SteamSentinel-0.3.0-preview.4-selfsigned-RELEASE-SHA256.txt` |
| 签名 | `SELF-SIGNED-PREVIEW`，无公共受信任证书链和时间戳 |

证书 `CN=fenglinbei`，指纹 `3395882D18D66EFA1545C1FE6DD867EB004176D1`，有效期至 2027-09-04 10:00:58 UTC。Windows 可能提示发布者不受信任；`SIGNER.cer` 仅含公钥，不自动修改系统信任。使用完整安装包，不单独替换 DLL。详见[签名说明](SIGNING.md)。

## 验收边界

本地修复基线完成 2,615 项完整原生回归，安装维护 56 项、机器状态 43 项，均无失败或跳过；89 项恢复专项、中文 100% 与英文 150% 合成 DPI 布局各 454 项及 3,526 对资源核验通过。真实历史记录只读验证区分当前磁盘状态与明确标记的内存重建，未将未知改成成功。

发行包从干净提交完整重编译，并强制重跑原生回归和两项安装器门槛；发布后的实际计数与源码身份见 `ACCEPTANCE-SUMMARY.json`、`SELFTEST-RESULTS.json` 及两个 `INSTALLER-*-RESULTS.json`。独立测试的计数不相加成一次完整回归；本地 dirty 修复包不能替代新发行包的身份。

本修订未重复 Windows 10/11 安装 GUI、真实感染恢复和物理跨屏测试；此前这些结果仍绑定各自构建。物理跨屏及 AMSI 健康排查暂停；旧版有条件迁移提示保留已接受的目视覆盖缺口。ISO/DVD 扫描不在承诺范围，基础扫描不调用 AMSI。缺失、不可信或仍被占用的旧结果继续阻断，不能按文件年龄或错误文案解锁。

首次本地 UI 复验曾由 WPF 自动启动窗口触发一次旧病例状态恢复；原未知结果保留，未重放处置。测试隔离已修正，之后用真实记录前后哈希确认测试不再写入该记录。私有原始证据不随发行包公开。

## 历史版本

- [preview.3 身份与分层验收](RELEASE-0.3.0-preview.3.md)：误报规则修正，保留其 Windows 10/11、静态语料与重启验证结果。
- [preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2)：安装短路径与旧图标迁移修复。
- [变更日志](../CHANGELOG.md)、[English quick start](QUICKSTART.en.md)、[安装升级规则](INSTALLER-UPGRADE-0.3.0.md)。
