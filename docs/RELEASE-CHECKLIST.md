# SteamSentinel 0.1.19 发布检查清单

本清单区分“可生成的预览证据”和“允许公开分发的正式发布”。预览通过不等于公开发布获准。

## 自动阻断项

- [x] `global.json` 精确固定 .NET SDK 10.0.400；所有项目提交 `packages.lock.json`，CI 与发布使用 locked restore。
- [x] 版本只从 `Directory.Build.props` 的 `VersionPrefix` 派生；程序集 `ProductVersion` 携带提交与 preview/dirty/release 身份。
- [x] Windows CI 显式写入并上传 SelfTest JSON，要求至少 795 项通过、0 失败、0 跳过，并核对 `version` / `buildIdentity`。
- [x] Preview 与 Release 输出目录及文件名分离；暂存完成后原子移动，已有目标一律拒绝覆盖。
- [x] 源码包使用 `git archive` 从构建快照生成；忽略文件不会进入源码或构建输入。
- [x] Release 要求工作树完全干净、`HEAD` 精确位于 `v0.1.19` 的签名注解标签。
- [x] Release 要求公开受信 Code Signing 证书、HTTPS RFC 3161 时间戳及签后 `Valid` / 时间戳复核；任何缺失都中止。
- [x] 包内 `VERSION.txt`、`SIGNING.txt`、`SHA256SUMS.txt` 与外层 `RELEASE-METADATA.json`、`SELFTEST-RESULTS.json`、发布哈希一同生成。
- [x] 安装器最低系统与程序目标均为 Windows 10 build 19041；升级清理旧版平铺在安装根目录的已知文档副本。

## 每个候选包必须人工完成

- [ ] 从空输出目录构建，不使用历史 0.1.16 产物，不修改或覆盖已发布文件。
- [ ] 核对 `RELEASE-METADATA.json` 的 commit/sourceTree 与预期源码一致；核对所有外层 SHA-256。
- [ ] 核对四个自有 DLL 的 FileVersion 为 `0.1.19.0`，ProductVersion 与清单的 BuildIdentity 完全一致。
- [ ] 保存 `SELFTEST-RESULTS.json`，确认 `passed >= 795`、`failed = 0`、`skipped = 0`，且 elapsedMs/version/buildIdentity 均存在。
- [ ] 在未安装旧版的 Windows 10 22H2 与 Windows 11 x64 上走完安装、普通权限启动、快速扫描、完整扫描与卸载。
- [ ] 从 0.1.16 覆盖升级，确认应用根目录不再残留旧 `COVERAGE-0.1.11.md` / `COVERAGE-0.1.12.md` 等平铺文档，`docs\` 结构与 README 链接一致。
- [ ] 核对 ArchiveWorker 入站/出站阻断规则精确绑定新安装路径，并验证卸载后规则移除。
- [ ] 在 100%–200% DPI、键盘导航、屏幕阅读器、高对比度和减少动画设置下检查主流程及错误信息。

## 处置安全验收

- [ ] 仅用无害合成文件验证扫描、取消、报告导出、计划预览和拒绝分支；不要执行恶意样本。
- [ ] 验证便携包只能扫描/导出，不能通过提权绕过 Program Files、ACL 与全清单门禁。
- [ ] 验证计划过期、SID 改变、输入哈希或目录指纹改变、结果冲突及重解析点时均 fail closed。
- [ ] 验证任何仍含活动记录的隔离事件（含旧事件）永久删除都会被 Broker 拒绝；不要为了删除样本而回滚。
- [ ] 仅对结构、路径均通过核验且所有记录已经 `RolledBack` 的无害空事件验证清理。
- [ ] 确认界面的 `Complete` / Full clean 仅是策略提示，不会成为 Broker 的删除授权证明。

## 公开发布仍需完成

- [ ] 获得公开受信任且在有效期内的 Code Signing 证书，确认在线撤销检查成功。
- [ ] 选定并记录稳定的 HTTPS RFC 3161 服务；验证程序、安装器与卸载器均带可用时间戳。
- [ ] 完成独立安全代码审计、解析器持续模糊测试和 Windows 环境矩阵。
- [ ] 设计签名规则更新、撤回、离线更新及防版本回退机制；当前版本没有在线更新器。
- [ ] 通过可信独立渠道固定发布标签、提交、证书指纹与 SHA-256；不要把未签名或自签名 Preview 冒充正式包。

如果上述公开发布项没有全部完成，交付物必须保持 Preview 标识并限于受控测试。
