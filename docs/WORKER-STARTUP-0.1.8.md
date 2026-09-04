# 0.1.8 管理员扫描启动修复

## 已定位的问题

本机 0.1.7 普通权限扫描正常，打开管理员窗口后，ArchiveWorker 在发送 Low 握手前以 `0xC0000142` 退出。该状态表示初始化失败，不能单凭此码认定 DLL 被删除。

只读检查发现，普通令牌默认对象权限包含当前用户完全访问，而关联管理员令牌主要授权 Administrators 和 SYSTEM。降为受限 Low 令牌后，管理员组不再提供有效授权，旧启动器却保留了管理员来源的默认对象权限。

在无害诊断中，将新受限令牌副本设为管理员式默认 DACL，可稳定复现启动失败。给该新令牌的当前用户 SID 正确授权后，同一组件恢复 Low 握手。未修改系统或当前进程的令牌权限，未运行样本。

## 修复范围

- `RestrictedTokenSecurity` 仅修改新建受限令牌的 TokenDefaultDacl 与 TokenOwner，默认对象授权当前用户与 SYSTEM。保留禁用最大特权、LUA、Low 完整性和单进程 Job，未添加 Everyone/Users 写权限。
- `RestrictedProcess` 保留创建时返回的原生句柄，不在进程退出后按 PID 重开。用进程信号判断是否结束，再读取原生退出码，避免将真实退出码 259 当作仍在运行。
- `ArchiveWorkerClient` 区分组件预检、创建受限进程、安全握手、内容扫描与退出阶段。握手限时 10 秒，非 Low/Untrusted 握手不发送扫描路径。错误输出有界保留并持续排空，清理时主动终止的退出码不作为原始故障码。
- Worker 失败或取消时仍释放句柄、Job 和临时工作目录。内容扫描失败保留已完成的系统/Steam 结果，导出报告携带阶段与可取得的退出码，覆盖状态为 Partial，不能当作完整干净复扫。
- 安装 ACL/哈希、Broker 的 SID/短时计划哈希、TOCTOU 复核及处置二次确认不变。没有将压缩解析改到管理员 UI 内执行。

## 本版验证

- Release 构建 0 警告、0 错误，自动回归 165 通过、0 失败、0 跳过。
- 管理员式默认 DACL 在令牌副本上构造，验证修复后的权限、Low、用户所有者以及来源未改变。另有正常生产 Worker 的真实握手与 EOF 退出测试。
- 无害工作进程模拟 `0xC0000142`、退出码 259、大量 stderr、非 Low 握手、返回结果后异常退出、握手超时和取消，验证故障信息与清理。
- 2026-09-04 17:25:52（UTC+8），通过 Windows RunAs 启动开发测试程序，实际父进程为 High，子进程回报 Low，受限令牌不是有效管理员。原始句柄读到握手后 EOF 退出码 2，随后无害文本/ZIP 内容扫描 Complete，3 次文件访问、1 个归档成员、0 项发现，调用方默认 DACL 未改变。
- 原始管理员验证报告保存在本机 `%PROGRAMDATA%\SteamSentinel\Results\v018-worker-smoke-20260904-092552-474da367626a4840ab3181c2394aa9bc\result.json`。首次尝试因原结果目录存在继承的普通用户写权限被测试前置检查拒绝，未开始扫描。测试随后使用新建受保护证据子目录，未改既有 ACL。无害输入已清理，报告保留，不随安装包发布。
- WPF 离屏检查扫描不完整、导出、错误详情与既有权限/密码布局。离屏截图不是实际安全桌面或高 DPI 操作验收。

## 验证边界与升级

本轮未启动恶意样本，未关闭防护，未重新运行完整样本库，扫描规则未变。管理员实测调用的是生产启动器和工作进程，未覆盖新版安装升级、实际 UI 按钮快速扫描、跨账户凭据或隔离/回滚/Steam 恢复完整流程。

退出旧版普通与管理员窗口，核对发布哈希，用 `SteamSentinel-0.1.8-setup.exe` 覆盖安装，不要只替换 EXE。先测试普通窗口，再测试管理员窗口的快速扫描。如果仍失败，请导出报告并附上阶段、退出码与当前权限状态。剩余群内验收见 `GROUP-TEST-GUIDE.md`。

参考：Microsoft [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)、[NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)。
