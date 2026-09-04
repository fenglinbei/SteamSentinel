# 签名构建与信任说明

构建脚本接受 `-SigningThumbprint`，从当前用户的 Personal/My 证书库选择带私钥、未过期且具有 Code Signing 用途的证书。没有此参数时构建明确标为未签名，不会自动生成证书或修改信任。

签名顺序为：发布程序 → 签署自有 EXE/DLL → 复制说明与公钥证书 → 生成组件 SHA-256 → 压缩程序及源码 → 签署卸载器和安装器 → 生成最终发布哈希。第三方运行时文件不重新签名，原有签名保留。源码包和程序包均不包含私钥。

当前朋友测试构建使用 `CN=fenglinbei` 自签名证书，RSA 3072、SHA-256，未添加可信时间戳。私钥设为不可导出，仅在本机证书库保存。证书不被自动导入受信任根或受信任发布者，也不随安装自动建立信任。

**签名完整性与公开信任是两回事。** 自签名不能证明发布者经过独立机构身份验证，不保证消除 Windows 未知发布者或 SmartScreen 提示。核对安装包哈希和证书指纹时，应通过已知可信的独立渠道确认，不应因为存在一个签名就关闭防护或盲目继续安装。

包内 `SIGNING.txt` 给出证书主题、指纹、有效期和签名类型，`SIGNER.cer` 仅含公开证书。没有可信时间戳的签名在证书过期后需要重新签发与发布。电脑或密钥丢失后将无法继续用这把不可导出的私钥签名，需要生成新证书并重新告知收件人。

复现签名构建（将示例指纹替换为明确选定的证书）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -SigningThumbprint <证书指纹>
```

不要把 PFX、密码或私钥放入源码仓库，不要向安装包添加自动信任证书或关闭防护的操作。正式公开分发前仍需要公开受信任的代码签名方案及相应发布验收。

参考：Microsoft [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)、[New-SelfSignedCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate)、Inno Setup [SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)。
