# 签名、时间戳与发布身份

SteamSentinel 0.1.19 把 Preview 与公开 Release 视为不同的信任等级。签名不能替代源码审查、发布哈希或安全软件；自签名也不代表发布者经过独立验证。

## Preview

`build-release.ps1` 默认生成 Preview。没有 `-SigningThumbprint` 时，包内 `SIGNING.txt` 明确记录 `UNSIGNED-PREVIEW`；显式选择自签名证书时记录 `SELF-SIGNED-PREVIEW`。脚本不会自动生成证书、导入信任、关闭防护或隐藏未知发布者提示。

Preview 文件名、程序集 ProductVersion、`VERSION.txt` 和 `RELEASE-METADATA.json` 均携带 commit；显式允许当前可跟踪改动时还携带 `dirty` 与源码树 ID。它们用于开发验收，不能因“有签名”而冒充正式公开包。

## 公开 Release 的 fail-closed 条件

`-Mode Release` 同时要求：

- 工作树完全干净，包含没有未跟踪文件；
- `HEAD` 精确位于与中央版本一致的 `v0.1.19` 注解标签，且 `git tag -v` 验证成功；
- 显式指定当前用户 Personal/My 库中带私钥、在有效期内且具有 Code Signing EKU 的证书；
- 证书不是自签名，并通过 Windows 在线链与撤销检查；
- 显式指定绝对 HTTPS RFC 3161 `-TimestampUrl`；
- SignTool 使用 SHA-256 文件摘要和 `/tr ... /td SHA256`，签后身份、`Valid` 状态及 TimeStamperCertificate 全部复核成功；
- 安装器和签名卸载器使用相同配置，最终安装器再经过同样复核。

缺少任何一项都会在原子发布前失败，不会降级为“看似正式”的未签名或无时间戳包。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 `
  -Mode Release `
  -SigningThumbprint '<40 位证书指纹>' `
  -TimestampUrl 'https://<可信 RFC3161 服务>'
```

这里故意不提供默认时间戳服务。发布负责人必须按证书颁发机构政策选择、记录并验证可用服务，不能把未经确认的第三方 URL 固化成信任根。

## 产物与验证

签名顺序为：从 Git 快照构建 → SelfTest → 发布自有组件 → 签署自有 EXE/DLL → 生成包内清单 → 压缩 → 签署安装器/卸载器 → 生成元数据和最终哈希 → 原子移动完整目录。第三方 .NET 运行时文件不重新签名，保留其原始签名。

包内 `SIGNER.cer` 只包含公钥证书，`SIGNING.txt` 记录主题、指纹、有效期、链检查和时间戳 URL；私钥、PFX、密码不会进入源码包或程序包。最终还应从可信独立渠道固定 tag、commit、sourceTree、证书指纹和 SHA-256。RFC 3161 时间戳可证明文件在证书有效期内完成签名，但不能赋予恶意或错误代码可信性。

不要把 PFX、密码、私钥或时间戳凭据放入仓库；不要向安装包加入自动信任证书或关闭防护的操作。当前项目仍缺外部安全审计与签名更新/撤回机制，在这些公开发布门槛完成前只生成 Preview。

参考：Microsoft [SignTool](https://learn.microsoft.com/windows/win32/seccrypto/signtool)、[Get-AuthenticodeSignature](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature)、Inno Setup [SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)。
