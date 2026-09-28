# 0.3.0 双语安装器

当前状态（2026-09-28）：双语安装器已随自签名预发布版 `v0.3.0-preview.2` 交付。中英文普通安装向导已逐页目视检查，最新修订的 Windows 10/11 安装、升级、重装及重启核验通过；旧版有条件迁移提示未目视检查为已接受保留项。见[发布说明](RELEASE-0.3.0.md)。下文为早期候选记录，“仍待验收”及仅创建缺失状态目录的描述属于当时实现；后续精确迁移策略见[安装升级说明](INSTALLER-UPGRADE-0.3.0.md)。

完整候选安装包已生成；修复布局后的 `65153b50b02b` 候选已通过虚拟机安装、升级、卸载及资源完整性 17 项专项。人工安装语言选择页和完整产品处置交互仍待验收。当前身份、哈希和后续样本复验见[联合验收记录](JOINT-ACCEPTANCE-0.3.0.md)；以下第一候选记录作为历史保留。

安装器提供 English 和简体中文选择，沿用同一 AppId、固定安装目录、快捷方式名和升级链。安装界面的选择与应用内按 Windows 用户保存的显示语言独立；安装器不替管理员或原用户改写应用语言偏好。

中文消息基于 Inno Setup 官方源码仓库 `is-6_4_3` 标签中的 `Files/Languages/Unofficial/ChineseSimplified.isl`，保留原维护者 Zhenghan Yang 的署名和注释。这是项目修改版：补齐当前编译器的 19 条新消息、注释 4 条已废弃消息，并补充 13 对安装器自定义提示。当前实际编译器为 Inno Setup 6.7.3；默认消息逐项核对为 293/293，参数占位符一致。原维护者来源和许可证见文末。

机器状态目录由固定路径的安装辅助脚本准备。它仅创建缺失目录，原子指定仅 SYSTEM/管理员可写的 DACL；对现有目录验证所有者、写权限、重解析点和锁定句柄的最终路径，拒绝把不可信现有目录通过改 ACL 变为可信。它不接受任意目标路径，不递归改权限，不删除隔离记录。安装前准备失败会停止；安装后再次验证，再配置和复核 Worker 网络阻断。

辅助脚本由安装器内嵌并校验 SHA-256，从 Inno Setup 的专用临时目录调用。当前 Inno Setup 对本地磁盘上提权进程的临时目录限制普通用户写入，联合验收还需核对实际安装环境中的目录权限。中文卫星资源 `zh-Hans/SteamSentinel.Core.resources.dll` 已纳入应用必需组件和完整性清单。

本轮中间证据位于 `work/v03-step7-20260921`：

- `installer-syntax-03.log`：语法夹具编译无警告。产物带 `DO-NOT-INSTALL`，不得用于安装测试。
- `installer-catalog-01.json`：293 个默认消息、13 对自定义消息，键与占位符检查通过，附源文件哈希。
- `installer-bootstrap-03/results.json`：在宿主机惰性目录中验证辅助类可编译、句柄检查可用、不可信已有目录被拒绝且 ACL 不变、普通文件被拒绝；未调用真实 ProgramData 准备入口。
- `installer-bootstrap-01`、`02` 保留测试脚本反射调用适配失败现场；`03` 为修正后的通过记录。
- `preview-build-03.log`：完整候选回归 2,204 通过、0 失败、0 跳过，真实双语安装器编译完成。安装包 SHA-256 为 `A0A58675391FFAB4D563815ED1B8DFC14F0385DD620108E21370E748B7EB377A`，源码树为 `b3b20510c26422b7b99bbb6b121e43e73d2e3c3c`。该候选为 `UNSIGNED-PREVIEW`，仅供已授权的隔离实验，发布范围待沟通。
- `joint-media-Scratch-01.json`、`joint-mount-Scratch-01.json`：只读验收介质的哈希、候选程序集一致性及精确虚拟机绑定；这两份回执只证明介质准备完成，不证明安装验收通过。
- `joint-Scratch-status.json`、`joint-Scratch-events`：第一候选在 Scratch 的中英文安装命令、升级、卸载保留数据、旧 15 文件哈希保持、缺失/篡改卫星资源、额外 DLL 拒绝、不可信非空状态拒绝及 ACL/内容保持均通过。新 Worker 扫描与双语 JSON 一致性通过；AMSI 仍为 Partial。安装测试读取了错误的注册表语言属性，值为 null，此项未计为通过，需补采正确属性或安装日志。

实际界面发现的英文详情标签间距问题已修复，两种语言布局各 352 项通过。后续候选的完整回归为 2,206 项通过；安装项目已复验，实际 `Inno Setup: Language` 记录、真实提权语言继承均已验证。安装器人工语言选择页面及其余联合场景仍按[联合验收记录](JOINT-ACCEPTANCE-0.3.0.md)跟踪。第一候选结果只归属于其固定 SHA-256，不覆盖后续构建。

来源：[中文原文件](https://github.com/jrsoftware/issrc/blob/is-6_4_3/Files/Languages/Unofficial/ChineseSimplified.isl)、[语言文件与编码](https://jrsoftware.org/ishelp/topic_languagessection.htm)、[Unicode 支持](https://jrsoftware.org/ishelp/topic_unicode.htm)、[临时目录安全措施](https://jrsoftware.org/is6help/topic_securitymeasures.htm)。

## Inno Setup License

Except where otherwise noted, all of the documentation and software included in the Inno
Setup package is copyrighted by Jordan Russell.

Copyright (C) 1997-2026 Jordan Russell. All rights reserved.
Portions Copyright (C) 2000-2026 Martijn Laan. All rights reserved.

This software is provided "as-is," without any express or implied warranty. In no event shall
the author be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial
applications, and to alter and redistribute it, provided that the following conditions are met:

1. All redistributions of source code files must retain all copyright notices that are currently
   in place, and this list of conditions without modification.

2. All redistributions in binary form must retain all occurrences of the above copyright notice
   and web site addresses that are currently in place (for example, in the About boxes).

3. The origin of this software must not be misrepresented; you must not claim that you wrote
   the original software. If you use this software to distribute a product, an acknowledgment
   in the product documentation would be appreciated but is not required.

4. Modified versions in source or binary form must be plainly marked as such, and must not
   be misrepresented as being the original software.

Jordan Russell

jr-2020 AT jrsoftware.org

https://jrsoftware.org/
