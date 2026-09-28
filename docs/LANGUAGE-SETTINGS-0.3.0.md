# 0.3.0 语言设置与导出

本页保留 2026-09-21 语言设置实现阶段的证据。2026-09-22 已生成双语候选，并实测跨账户管理员窗口继承当前语言、独立用户偏好和下次启动生效；最新结果见[联合验收记录](JOINT-ACCEPTANCE-0.3.0.md)。用户已批准下表中的行为。

## 已冻结的行为

| 项目 | 规则 |
| --- | --- |
| 界面语言 | 自动 / 简体中文 / English。自动依据当前 Windows 用户的显示语言，中文使用简体资源，其余使用英文 |
| 保存和生效 | 按当前 Windows 用户保存；下次启动生效。保存时显示结果，当前窗口、扫描、处置和弹窗保持原状 |
| 管理员窗口 | 继承发起窗口的实际显示语言，即使用户刚保存了另一种下次启动语言。继承只作用于新窗口，不覆盖目标账户的偏好 |
| Markdown 与记录包 | 默认跟随当前实际界面语言；允许本次另选简体中文或 English。取消选择即取消本次导出，不改变用户偏好 |
| JSON 和原始记录 | 不添加显示语言字段；导出同一报告对象时 JSON 逐字节相同。原始标题、证据、系统错误和旧自由文本保持原文，Markdown 与包内说明提示其来源 |

语言选择不参与规则命中、严重度、动作资格、权限或验证状态的判断。新扫描自身的时间、身份和原始生产者文字可能不同，“JSON 相同”指同一对象只改变导出语言的情况。

## 中文使用说明

1. 打开主窗口的“语言 / Language”页，选择下次启动使用的语言，点击“保存语言设置”。完成正在进行的工作后，下次正常启动即可使用新语言。
2. 导出 Markdown 报告或记录包时，选择保存位置后会出现“本次导出语言”。默认跟随当前界面，也可单独选择简体中文或 English；JSON 证据导出不需要选择语言。
3. 如果提示设置无法读取或无效，可在语言页重新选择并保存。保存失败时旧设置仍保留；当前窗口不切换语言。

## English usage

1. Open the **Language** tab (shown as **语言 / Language** in Chinese), choose a language for the next launch, and select **Save language**. The current window and any running task keep their current language. The new choice applies the next time the app starts.
2. When exporting a Markdown report or record bundle, choose the destination and then select **Language for this export**. It defaults to the current interface. You can choose Simplified Chinese or English for this export only. JSON evidence exports do not ask for a language.
3. If the saved setting cannot be read or is invalid, choose and save a language again. A failed save preserves the previous setting. Original evidence and older records retain their original language.

## 实现与兼容

- 设置保存在 `%LOCALAPPDATA%\SteamSentinel\ui-language.json`，仅包含 `SchemaVersion: 1` 和 `Language: auto / zh-Hans / en`。最多读取 4,096 字节，拒绝重复键、未知字段、未知版本和语言值。缺失文件使用自动，不创建文件。
- 损坏或读取失败不改写设置文件，回退自动并显示提示。有效管理员继承参数优先决定本窗口显示；设置页仍显示目标用户自己的偏好及读取情况。
- 保存先创建独立临时文件、完成写入并刷新，再替换旧文件。写入或替换失败会清理本次临时文件并提示错误。
- `App.OnStartup` 在创建 WPF 视图前设置 `DisplayText` 的进程默认语言；显式导出语言作用域可覆盖默认值。后台任务也能读取默认值，不改变 `CurrentCulture`、`CurrentUICulture`、数值解析和机器字段。
- 管理员启动仍只执行受保护安装目录中的固定应用，并保留安装验证。新增参数仅允许固定组合 `--administrator-window --ui-language zh-Hans|en`，兼容原单独管理员标记。其他参数整体忽略并提示，不传递路径、报告、处置计划或凭据。该标记不是权限证明，跨账户仍须重新扫描。
- 普通导出和病例导出共用语言选择窗口。JSON 保持原流程；ZIP 保留 `scan.json`、`说明.txt` 等既有名称；导出继续使用原来的脱敏、原子写入及不打包样本/密码规则。
- 本批新增 20 组资源，共用资源累计 1,182 组，加 67 组状态资源，共 **1,249 组**。简体中文 / English 选择项使用语言自身名称，方便用户从另一种语言切回。

## 本轮验证

证据目录：工作区 `work/v03-step6-language-20260921/`。`validation-summary.json` 保存构建、资源、源码及结果的 SHA-256。

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| Release 构建 | 0 警告、0 错误 | 构建工具输出及汇总中的程序集身份 |
| 中文真实 WPF | 350 通过，0 失败 | `layout-01-zh-Hans/layout-test-results.json` |
| 英文真实 WPF | 350 通过，0 失败 | `layout-01-en-US/layout-test-results.json` |
| 资源与受影响回归 | 356 通过，0 失败 | `resources-01/results.json` |
| 设置、启动、导出与既有提权边界 | 97 通过，0 失败 | `language-02/results.json` |
| 静态资源审计 | 1,249 对，0 错误 | `resource-audit.json` |

设置测试覆盖首次运行、四种 Windows 语言、全部偏好往返、16 类无效文档、4,096 字节边界、未知枚举、保存占用失败、读取失败和参数拒绝。五个独立新进程验证实际主窗口按钮与后台默认语言，包括中文到英文的下次启动、自动映射和管理员继承。跨账户通过独立设置路径模拟，不等同于真实跨账户 UAC 验收。

WPF 检查保留原主窗口和弹窗断言，并增加设置页实际保存、失败提示、当前窗口不变、导出默认值与语言选择。人工核对了中英文 440×340 设置页和 440×280 导出窗口截图；较小页面、按钮和说明均可读。该尺寸是测试内容视口，不代表 Windows 外框或其他 DPI 已验收。

首次设置专项在预期的文件占用失败处返回 `UnauthorizedAccessException`，原测试只捕获 `IOException`，导致后续检查未运行。已补齐测试对两种失败类型的处理；生产保存代码和界面异常处理不需要修改。保留 `language-01` 的原始失败结果。UI / 资源回归使用修正测试前的构建，设置专项使用修正后的 SelfTest；两次构建的生产程序集哈希一致，当前五处中文卫星资源副本一致，测试程序集差异单独留档。

## 剩余范围

后续后台消息迁移和双语安装器已实现，资源安装升级、完整源码回归及真实提权语言继承已验收；[英文快速使用说明](QUICKSTART.en.md)已补齐。其余 DPI、完整产品权限交互及三台样本复验的剩余项目见[联合验收记录](JOINT-ACCEPTANCE-0.3.0.md)。本页早期设置专项没有执行样本或真实处置，不等同于后续结果；旧构建记录仍不替代当前构建证据。Preview/RC 与发布范围须在冻结前另行沟通。
