# 0.3.0 安装文件升级策略 / Installation file upgrades

安装器先检查已有安装目录，再复制新版文件。复制完成后，只移除内置清单中已经核实、且新版不再提供的旧文件，最后校验完整安装目录。安装前检查失败会阻止替换；复制后的维护或校验失败会阻止报告成功及自动启动。失败日志说明具体相对路径和原因；部分移除后发生系统错误时，日志也保留已经处理的条目。这不构成整套安装事务回滚的承诺。

Setup checks the existing installation before replacing files. After copying the new payload, it retires only approved obsolete bytes absent from the incoming package, then verifies the complete installed file set. A failed preflight stops replacement; a failed maintenance or postflight stops successful completion and automatic launch. Diagnostics identify the relative path and reason, including completed retirements if a later operation fails. This is not a transactional rollback guarantee.

The embedded retirement catalog contains exactly:

| Relative path | Bytes | SHA256 |
|---|---:|---|
| `mscordaccore_amd64_amd64_10.0.1126.37416.dll` | 1356632 | `C1B92DA5356BB36F4AB55AA54B2D25A8A27518CF7A456EB4957DDFE94E2D428C` |
| `SIGNER.cer` | 1022 | `927392458711531A02B5DDF3AE170C79059EFCBBEE90AD3A453EFE939B2C2255` |

新包内的文件清单和维护组件由安装器编译时的 SHA256 绑定。旧的本地清单不授予删除权限。若新包包含 `SIGNER.cer`，按普通新文件替换、校验，不能被旧证书清理规则移除。未知旧文件或内容不符的同名文件保留原件并阻止升级，需复核后重试。不得建议用户搬动文件来绕过检查。

The incoming manifest and maintenance components are bound to hashes embedded at installer compilation. An old local manifest grants no deletion permission. If the incoming package includes `SIGNER.cer`, normal replacement and verification apply. Unknown obsolete files and changed content at an approved old filename are preserved and block the upgrade for review. Moving files to bypass this check is not a remediation procedure.

维护入口固定在受保护的 Program Files 安装目录，没有可选安装根或自定义清理清单。验证拒绝重解析路径、硬链接、不可信写权限和占用冲突；清理使用已固定的目录及文件句柄，全部待处理项通过二次检查后才开始移除。不清理或修改用户设置、扫描报告、案例、隔离数据、机器状态目录、Windows 证书存储或私钥。

The production entry point fixes the application directory under Program Files and accepts no alternate installation root or retirement catalog. It rejects redirection, hard links, untrusted writers and sharing conflicts, and rechecks held handles before retiring any target. User settings, reports, cases, quarantined data, machine-state directories, certificate stores and private keys are outside this operation.

上述是维护组件的操作边界，并不承诺历史合并卸载记录保留空目录。实际从 0.2.0 升级后，正式卸载器可能按旧记录移除空的机器状态目录；应分别核验目录/权限与真实用户记录，不能把“用户记录保留”写成“所有历史空目录绝对不变”。维护组件不会借此自动恢复或修改状态权限。

This is the maintenance component's boundary, not a promise that merged historical uninstall logs preserve empty directories. After a 0.2.0 upgrade, the official uninstaller may remove empty machine-state directories recorded by the old installation. Verify directories/ACLs separately from user records; preserving records does not imply all historical empty directories remain unchanged. Maintenance does not automatically recreate them or change their permissions.

早于 0.1.17 的 17 个平铺说明文件不再按名称直接删除。没有审定内容哈希时，它们也属于需人工复核的未知旧文件。本轮自动清理覆盖已经验真的两套 0.2.0 验收基线，不声称覆盖所有未知旧构建。增加兼容项必须另行核实并扩展内置清单。机器状态权限由下面的独立初始化流程处理，不属于旧文件清理目录。

The former filename-only deletion of 17 pre-0.1.17 documentation files has been removed. Without approved historical content hashes, those files also require review. The current catalog covers the two verified 0.2.0 acceptance inputs; it does not claim universal historical-build compatibility. Additional entries require verified provenance. Machine-state permissions are handled separately as described below, outside the file-retirement catalog.

## 旧版无数据状态目录 / Empty legacy state directories

部分 0.2.0 安装会在 `ProgramData\SteamSentinel` 及三个子目录中留下继承的普通用户写权限。安装器只对来源已经核验、权限符合审定旧模板的无数据目录树进行迁移：根中只能有 `Quarantine`、`Results`、`BrokerTemp` 三个固定空子目录（允许缺失项安全创建）。仅收紧这些目录的 DACL，保留可信原所有者；系统和管理员可以写入，普通用户只对非 BrokerTemp 目录保留读取权限。已有安全目录的权限不重写。安装确认页说明迁移，静默安装采用相同门槛。

Some 0.2.0 installations left inherited standard-user write permissions on `ProgramData\SteamSentinel` and its three subdirectories. Setup migrates only an empty tree with verified installation provenance and an approved legacy permission pattern. The root may contain only the three empty directories `Quarantine`, `Results`, and `BrokerTemp`; missing directories are created securely. Only their DACLs are restricted, retaining trusted ownership. System and Administrators retain write access; standard users retain read access outside BrokerTemp. Already-safe permissions are not rewritten. The confirmation page explains the migration, and silent setup uses the same checks.

弱权限目录一旦含文件、未知子目录或其他未知内容，安装即停止。不会递归改权限、删除内容，或把原先可能由普通用户写入的案例和隔离记录重新认定为可信。目录所有者、权限模板、路径身份、重解析或占用检查失败时，同样保留现场并显示中英文原因。实际路径和阶段记入安装日志；不要求用户通过搬走记录来绕过保护。

Files, unknown subdirectories, or other unexpected content in a writable legacy tree stop setup. Setup does not recursively rewrite permissions, delete content, or confer trust on records that standard users could previously modify. Unsupported ownership or permission patterns, redirected paths, changed identities, and sharing conflicts also stop setup with localized reasons and diagnostic paths. Moving records aside to bypass this protection is not a supported recovery procedure.

迁移开始前写入仅系统/管理员可写的安装器进度记录，逐项记录目录身份和实际完成的权限修改。中断不承诺事务回滚：已经收紧的权限不会恢复为弱权限。下次安装先检查未完成记录，仅在身份及无数据条件仍符合时继续；否则保留现场并停止。`Verify` 只复核，不执行迁移。该记录不加入用户报告格式，也不影响扫描状态或原因码。

A protected installer progress record tracks directory identities and completed permission changes before migration starts. This is not a transactional rollback: permissions already restricted are not restored to their weaker form. A later run checks unfinished progress and resumes only if identity and empty-tree conditions still hold; otherwise it preserves the state and stops. Verification never performs migration. Installer progress does not change user report schemas or scan status codes.

构建门禁：`scripts/build-release.ps1` 必须在提升权限的 Windows 环境运行归档源码中的 `Test-InstallerPayloadMaintenance.ps1`。专项使用新的无害临时文件，零失败、零跳过，并绑定实际源码和测试脚本哈希；结果另存 `INSTALLER-MAINTENANCE-RESULTS.json`，纳入发布元数据及外层校验清单。核心 2358 项自检门禁保持独立，安装器专项不能替代真实 Windows 10/11 安装与升级验收。

Release builds require elevated Windows execution of the archived maintenance tests. These use new inert temporary fixtures, require zero failures and zero skips, and bind the actual source and test script hashes. The separate results enter release metadata and the outer checksum list. The existing 2358-test application gate remains independent; neither gate replaces actual Windows 10/11 package acceptance.

机器状态迁移另有归档源码专项 `Test-InstallerMachineState.ps1`，使用隔离的无害目录及测试注册表键，结果保存为 `INSTALLER-MACHINE-STATE-RESULTS.json`，独立要求零失败、零跳过及源码绑定。真实旧版升级仍必须从未经手动修复权限的现场验证，不能用已经收紧过权限的实验机替代。

Machine-state migration has a separate archived-source test gate using isolated inert directories and test registry keys. `INSTALLER-MACHINE-STATE-RESULTS.json` binds the tested source and requires zero failures and skips. Real upgrade acceptance must also start from unchanged legacy permissions; an already-hardened lab machine does not establish that migration works.
