# 应用图标

图标使用内置 image_gen 生成，用于 SteamSentinel。未使用 CLI/API 回退，也未使用 Steam 或 Valve 官方标志，不表示官方关联。

- 原始 PNG：`SteamSentinel.App/Assets/App.png`，保留生成图像透明通道。
- Windows ICO：`SteamSentinel.App/Assets/App.ico`，包含 16、20、24、32、40、48、64、128、256 像素图层。
- 接入位置：EXE 资源、主窗口、应用页头、安装器与卸载显示图标。
- 使用 Windows PowerShell 执行 `scripts/build-icons.ps1` 可从 PNG 重新生成 ICO，仅进行格式与尺寸转换，不重新设计图像。PNG 与 ICO 一并纳入源码管理。

## 最终生成提示词

```text
Use case: logo-brand. Asset type: production Windows desktop application icon, single square 1024x1024 PNG, genuinely transparent outside the icon, preserve alpha. Create an original polished fluent-style icon, straight-on orthographic view, strong silhouette readable at 16 to 48 pixels. A rounded-square tile occupies about 90% of the canvas with equal narrow margins, corner radius about 22%, subtle top-left illumination and restrained soft bevel. A single large, bold off-white foreground symbol with balanced padding, no thin lines or fine details. Professional friendly security utility, not a game illustration. No text, no letters, no numbers, no Steam/Valve official logo or other trademarks, no badges, no watermark, no mockup, no checkerboard painted into background, no external cast shadow. Primary request: icon for 'SteamSentinel', a Steam threat scanning, isolation and recovery tool. Color palette: deep navy #17324D to cobalt #2563AB rounded-square tile. Foreground symbol: a large simple white protective shield, with a single bold dark-blue wrench silhouette cut into its center, angled gently from lower-left to upper-right, conveying protection and repair. Only these two integrated shapes, highly legible and dependable.
```
