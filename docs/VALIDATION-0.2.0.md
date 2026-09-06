# 0.2.0 验证入口与交付边界

本文件说明如何核对本次 Preview。具体构建身份、完整自检计数、文件哈希及构建时间以交付目录中的 `RELEASE-METADATA.json`、`SELFTEST-RESULTS.json`、版本前缀 `RELEASE-SHA256.txt` 和包内 `SHA256SUMS.txt` 为准。源码归档与二进制来自同一个不可覆盖的 Git tree 快照；`dirty.preview` 明确表示该快照含尚未提交的开发成果。

发布脚本仍运行默认完整自检，要求零失败、零跳过且达到中央测试基线。专项结果是不同入口的独立运行，不能与完整自检相加后宣称更多互不重复的测试。

| 验收项 | 验证方式 | 结论的适用范围 |
|---|---|---|
| A01 多层链 | `--v020-worker-topology` 对 Small 惰性夹具逐一核对 167 个最终成员的长度、SHA-256、完整性、父链和三卷复用，并主动恢复副本 | MP4 尾随 AES ZIP、加密 RAR、三分卷、改名 RAR 和 RAR SFX 的指定同拓扑 |
| A02 实体大文件 | 同一入口对 Large 清单运行；记录 Worker 构建与组件哈希、读取/解码/展开量、临时峰值、内存和耗时 | 根文件及多层成员超过 1 GiB、解码超过旧 4 GiB；不扩大为任意大小文件 |
| A03 64 位边界 | `V020ContainerResourceTests` 检查 1/2/4 GiB 前后 1 字节、范围相加溢出与嵌套范围 | 虚拟范围用于偏移边界，Large 另提供非稀疏实体证据 |
| A04—A05 分卷及失败 | `V020ArchiveVolumeTests`、RAR 完整性与 ZIP 跳过回归 | 具体受支持形式见实现说明；缺卷、混卷、错序、损坏和不支持完整性保持缺口 |
| A06 密码 | 既有 0.1.19 密码边界、作用域和多格式回归，加上新的固实/跨卷校验 | 错误尝试仍收费；新扫描清空；报告与外部命令行不保存密码 |
| A07 资源、终止 | 共享资源、原生 MSI/CAB、恢复安全测试，以及 `--v020-worker-boundaries` 的大实体取消、1 秒限时、合法磁盘保留不足注入 | 不合作组件另有真实 Job 硬截止回归；物理慢介质性能矩阵仍待专门设备验证 |
| A08 格式边界 | `V020ContainerRangeTests` 与 UnknownRange 集成回归 | MP4 box、PE/证书表、归档结束和未知残留；不分析媒体 box 内任意隐写 |
| A09 签名 | `--v020-signature` 静态检查有效签名的无害程序副本及仅修改代码节的副本，另有离线状态映射回归 | 不执行副本、不改系统信任库；当前是嵌入式文件签名检查，不声明覆盖目录签名 |
| A10 展示及交付 | 容器合并/检查点/恢复导出回归及 `--layout-ui` 实际 WPF 布局 | 长路径、长文本、小窗口、原始目标、独立扫描来源及秘密文本脱敏 |

最终包复验使用明确指定的已发布 `SteamSentinel.ArchiveWorker.exe` 路径，结果同时记录 Worker EXE、Worker DLL 与 Core DLL 的 SHA-256。布局复验从独立测试目录加载与交付包逐字节相同的 App/Core 程序集；不改写已经生成的包。机器实测与逐项结果另随交付说明提供。

基础入口（在已构建的 SelfTest 目录运行）：

```powershell
./SteamSentinel.SelfTest.exe --results SELFTEST-RESULTS.json
./SteamSentinel.SelfTest.exe --v020-tests ./v020-tests
./SteamSentinel.SelfTest.exe --layout-ui ./layout
./SteamSentinel.SelfTest.exe --v020-worker-topology SMALL-MANIFEST.json ./small PUBLISHED-WORKER.exe
./SteamSentinel.SelfTest.exe --v020-worker-topology LARGE-MANIFEST.json ./large PUBLISHED-WORKER.exe
./SteamSentinel.SelfTest.exe --v020-worker-boundaries LARGE-MANIFEST.json ./boundaries PUBLISHED-WORKER.exe
./SteamSentinel.SelfTest.exe --v020-signature SIGNED-BENIGN.exe ./signature PUBLISHED-WORKER.exe
```

拓扑工具只接受生成的公开密码惰性夹具清单，不能把实际取证包或密码当成该入口的参数。无害大文件生成脚本单独位于 `scripts/New-V020ValidationCorpus.ps1`；开发用打包器不随产品交付，也不是产品扫描依赖。

本包沿用用户接受的 Preview 边界。真实恶意配置规则、证书/代理原生变更与恢复、重新写入和跨重启复验、干净 Windows 10/11 安装升级矩阵以及正式公开签名发行，仍需各自验收。单次静态扫描通过、恢复副本成功或未检出，均不能替代这些门槛。
