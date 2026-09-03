# 0.1.4 group preview 测试证据

测试日期：2026-09-04（Asia/Shanghai）

## 自动回归

`SteamSentinel.SelfTest` 在本机 Release 构建中通过 42 项、失败 0、跳过 0，覆盖：

- 规则集载入、真实文件类型、PE 改名 MP4、最小 MP4、MP4 尾随 ZIP。
- 改后缀压缩包、路径穿越、嵌套家族字符串、解压炸弹压缩比限制、快速模式小文件哈希。
- 加密 RAR 密码请求、正确密码完整扫描、拒绝密码后 `Partial`。
- ArchiveWorker 协议及密码往返，以及受限令牌 Low Integrity + 单进程 Job Object 的端到端握手。
- 处置计划精确 SHA-256、请求者 SID 绑定、计划被改写后的拒绝路径、锁定句柄上的 1 MiB 大小上限、JSON/Markdown 报告导出。
- 只新建不覆盖的结果文件、目录内容变化导致指纹变化、计划任务路径穿越/后缀冒充拒绝。
- 句柄绑定的无害文件复制、隔离副本哈希复核与源文件删除。
- 发现分类、扫描覆盖状态和处置动作的中文展示映射。
- Steam 多库发现、系统与 Steam 只读扫描。
- Wallpaper Engine `defaultprojects` 误报抑制。
- `steam.cfg` 成对禁更、固定真值红信、游戏重定向、第三方客服路由与隐藏地址栏。
- JSON 异步读取在非泵送同步上下文中不捕获调用方上下文，防止 WPF 同步等待型死锁回归。
- `ServiceApp.exe` 精确哈希、候选进程名、非主库 Workshop 路径与 `ServiceAppMscopiAuto` Run 项关联。
- 同一映像对应两个 PID 时生成两个停止动作、一个隔离动作，且所有停止动作排在隔离之前。
- Steam 退出门禁匹配 `steam.exe` 与 `steamwebhelper.exe`，不把 SteamSentinel 自身误判为 Steam 客户端。

## 真实样本静态验证

仅静态读取隔离副本 `WindowsUpdatem.exe.quarantined`，未执行样本。SHA-256：

`015D7391062205C3D5FAF06771E51C49989CF394411957541DDC9CE62771568B`

结果：覆盖 `Complete`；命中 `STEAMRED-EXE-001`（Critical，100 分），并同时命中扩展名/真实格式不一致与家族字符串线索。

新增证据样本静态回归（均未执行）：

- `wallpaper假红信盗号8月25.rar` 内 `ServiceApp.exe`：仅经内存解压流读取，大小 865,792 字节，SHA-256 `B0F17D38174E22DCB175663A7B904C3C532BDC9AA93531F988DE3F19DDEE2B7A`，加入 `STEAMRED-SERVICEAPP-EXE-001`。
- `DesktopNotify.exe`：命中 `STEAMRED-DESKTOPNOTIFY-EXE-001`，Critical 100。
- `notify_bridge.dll`：命中 `STEAMRED-NOTIFYBRIDGE-DLL-001`，Critical 100。
- `_svc_launch.bat`：命中 `STEAMRED-SVCBAT-002`，Critical 100。
- `chunk~2dcc5aaf7.js`：命中 `STEAMRED-STEAMUI-JS-001`，Critical 100。

## 管理员 Broker 集成测试

对程序生成的无害 UTF-8 文本执行了三次独立 UAC 动作：

1. 按计划 SHA-256 隔离，确认原文件消失、隔离副本存在、清单原子落盘。
2. 按事件 GUID 回滚，确认原内容恢复、清单记录 `RolledBack=true`、不覆盖现有目标。
3. 删除已完整回滚的测试事件，确认隔离目录移除，且回滚/删除动作没有新建空事件目录。

测试结束时，无害目标和测试隔离事件均已清理。

上述三步是 0.1.3 基线的实际 UAC 集成记录。0.1.4 已将集成测试计划更新为“计划 SHA-256 参数 + 固定受保护结果目录 + 管理员窗口二次确认”，需要在安装包落地的测试机上重新执行，列入群内发布门槛，不以单元测试代替。

## GUI 验证

- 主窗口三个页面在当前 Windows 缩放下完成视觉检查。
- 文件选择、独立扫描进程、加密包密码请求、跳过后 `Partial` 已端到端验证。
- 初测发现密码弹窗按钮在当前缩放下被裁切，已将窗口改为可调整大小并增加最小高度；复测按钮完整可见。
- 自动化框架不能向 WPF `PasswordBox` 注入秘密值；GUI 正确密码提交由人工检查项保留，底层正确密码流程已由 Worker 自动回归覆盖。
- 0.1.2 起将隔离清单刷新改为全异步；已使用现存真实隔离清单验证启动、进入隔离页及手动刷新后窗口保持响应，清单内容持续可见。
- 首轮复测暴露“已重启”只读属性被复选框默认双向绑定的问题；改为显式单向绑定后再次复测，未再出现未处理错误弹窗。

## 依赖与构建

- `dotnet build`：0 警告、0 错误。
- `scripts/build-release.ps1 -ReplaceExisting`：Release 构建与 42 项自检通过，成功生成 win-x64 便携扫描包、源码包和 Inno Setup 安装包。
- Inno Setup 6.7.3 编译成功；安装/卸载与 Program Files 运行时门禁仍需在干净测试机做一次实际验收。
- `dotnet format --verify-no-changes`：格式化后应通过。
- NuGet `--vulnerable --include-transitive`：当前源未报告已知易受攻击包。
- NuGet `--deprecated --include-transitive`：当前源未报告弃用包。
