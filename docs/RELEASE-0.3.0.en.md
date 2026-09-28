# SteamSentinel 0.3.0 remediation revision 4

Updated September 29, 2026. [简体中文](RELEASE-0.3.0.md)

This revision is [v0.3.0-preview.4, a self-signed Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.4). Product version remains **0.3.0**, with rules `2026.09.28.1`. It fixes eligible findings being selectable while the review/remediation button stays disabled by an old unresolved operation.

## Install and use

Close ordinary and administrator SteamSentinel windows, upgrade with `SteamSentinel-0.3.0-preview.4-selfsigned-setup.exe`, and rescan the original folder. No case deletion or manual configuration edits are needed. Startup checks previous operations automatically. An explanation beside the button provides the appropriate next step: **Check and continue**, **Scan again**, or **View records**.

Once an authenticated previous operation is confirmed finished, its unknown outcome no longer permanently blocks a new plan. Unknown history remains unknown, and saved plans are never replayed. Remediation scope, file identity and strong-evidence requirements remain in force. See the [recovery design](REMEDIATION-RECOVERY-0.3.0.md).

## Identity

| Field | This revision |
| --- | --- |
| Tag / product | `v0.3.0-preview.4` / `0.3.0` |
| Platform / self-contained runtime | Windows x64, minimum Windows 10 build 19041 / `.NET 10.0.12` |
| Rules | `2026.09.28.1` |
| Exact installer, source commit/tree and SHA-256 | Release attachments `PUBLICATION-IDENTITY.json`, `RELEASE-METADATA.json`, and `SteamSentinel-0.3.0-preview.4-selfsigned-RELEASE-SHA256.txt` |
| Signature | `SELF-SIGNED-PREVIEW`; no publicly trusted chain or timestamp |

The certificate is `CN=fenglinbei`, fingerprint `3395882D18D66EFA1545C1FE6DD867EB004176D1`, expiring September 4, 2027 at 10:00:58 UTC. Windows may report an untrusted publisher. `SIGNER.cer` is public-key material only; system trust is not changed automatically. Install the complete package. See [signing](SIGNING.md).

## Acceptance scope

The local repair baseline passed 2,615 complete native checks, 56 installer-maintenance checks and 43 machine-state checks, with no failures or skips. Recovery checks passed 89; Chinese at 100% and English at 150% synthetic DPI each passed 454; all 3,526 resource pairs passed validation. Read-only historical-record validation separates actual disk state from an explicitly labelled in-memory reconstruction and never rewrites unknown outcomes as success.

The publication package is fully rebuilt from a clean commit with mandatory native and installer gates. Exact results are recorded in `ACCEPTANCE-SUMMARY.json`, `SELFTEST-RESULTS.json` and the two `INSTALLER-*-RESULTS.json` attachments. Independent runs are not added together, and the earlier dirty local package is a separate build identity.

Windows 10/11 installation GUI, live infection/recovery and physical cross-monitor tests are not repeated for this revision. Earlier results retain their original build identities. Physical cross-monitor and AMSI health investigations remain paused; the conditional legacy-migration notice retains its accepted visual coverage gap. ISO/DVD scanning is outside the promised scope. Baseline scans do not call AMSI. Missing, untrusted or still-open old result files continue to block remediation; age or message text cannot authorize recovery.

The first local UI regression inadvertently opened a product window through WPF startup and recovered one historical case state. The unknown receipt was preserved and no remediation was replayed. Test startup is now isolated; subsequent file-hash guards confirm no further writes to that record. Private original evidence is not published.

## History

- [Preview.3 identity and acceptance](RELEASE-0.3.0-preview.3.en.md): false-positive rule correction and its own Windows 10/11, static-corpus and reboot results.
- [Preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2): short-path installation and exact legacy-icon migration fixes.
- [Changelog](../CHANGELOG.md), [English quick start](QUICKSTART.en.md), [installer migration](INSTALLER-UPGRADE-0.3.0.md).
