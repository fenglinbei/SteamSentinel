# SteamSentinel 0.3.0 release identity and acceptance index

Updated September 28, 2026. [简体中文](RELEASE-0.3.0.md)

Product version **0.3.0** is published as the [v0.3.0-preview.2 self-signed Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2), installer revision **2**. This page describes the current release; older plans, implementation records and source snapshots retain their original historical status. The GitHub Pre-release designation remains in effect; this is not a publicly trusted signed release.

## Download and provenance

| Field | Published identity |
| --- | --- |
| Release tag | `v0.3.0-preview.2` |
| Product / platform | `0.3.0` / Windows x64; installer minimum Windows 10 build 19041 |
| Self-contained runtime | `.NET 10.0.12` |
| Installer | `SteamSentinel-0.3.0-preview.2-selfsigned-setup.exe` |
| Installer SHA-256 | `0A3DC1284BFC029E454316B89DC08A9216CBAF8411E3608C5EE85A51C9BFD2D7` |
| Tagged source snapshot commit | `5878b6139caaf7cab90c647eb92c9c5d8a6febc6` |
| Tagged source tree | `1f9a0d2125dff8be2c72c8e8a2c16bd6bd271fd2` |
| Original product build identity | `0.3.0+e645c27207d406721a67e3d13ae0ec2f7e43449e.dirty.preview.7639ef7cb1eb` |
| Original product source tree | `7639ef7cb1eb885661d054321279879d7058c2ae` |
| Signing | `SELF-SIGNED-PREVIEW`; no public trust chain or timestamp |

Use the complete installer from the release page and check the [SHA-256 manifest](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/SteamSentinel-0.3.0-preview.2-selfsigned-RELEASE-SHA256.txt), [PUBLICATION-IDENTITY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/PUBLICATION-IDENTITY.json) and [RELEASE-METADATA.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-METADATA.json). A shared product version does not mean identical installer revisions or build provenance.

The certificate is `CN=fenglinbei`, SHA-1 fingerprint `3395882D18D66EFA1545C1FE6DD867EB004176D1`, expiring `2027-09-04 10:00:58 UTC`. Windows may report an untrusted publisher. `SIGNER.cer` contains only the public certificate; system trust stores were not changed. See the release's `SIGNING.txt` and [signing documentation](SIGNING.md).

All seven product binaries are byte-identical to preview.1; product code was not recompiled. Of the payload files, 529 are unchanged; only the installation migration document and `VERSION.txt` changed. Setup was rebuilt and signed from the corrected source. All 400 source ZIP files match the tagged tree after Git line-ending normalization. Executables retain their original dirty Preview identity, without claiming a clean rebuild from the subsequently created source snapshot commit. Later main-branch documentation updates do not change the published files, hashes, tags or acceptance identities.

## Installer revision 2

- Resolve legitimate Windows short names, such as `ADMINI~1`, that previously caused `Code=UnsafePath; Path=; Mode=Preflight`. Real handles and pinned parent directories preserve rejection of reparse redirection, hard links and untrusted writers.
- Add exact migration entries for early 0.3.0 `Assets\App.ico` and `Assets\App.png`. Both approved size and SHA-256 must match; modified or unknown files are preserved and block the upgrade.
- Include the path role, stage, input and actual path in failure diagnostics.

For the older installer's short-path error, close the ordinary and administrator application windows and run revision 2. Do not manually remove old files or weaken directory permissions. See [installation upgrade behavior](INSTALLER-UPGRADE-0.3.0.md) for migration eligibility and record retention.

## Product changes in 0.3.0

- Detection covers the studied SmartPet, TianLai and Scratch variants, including original packages, core components, verified derived payloads and component relationships. ZIP Chinese member names are handled correctly; Steam HTML, CSS, JS and support-route observations retain per-file evidence.
- Simplified Chinese and English settings are saved per user for the next launch. Markdown reports and record bundles can use a separate export language. Stable states and reason codes are separate from display text; original evidence and historical free text retain their language, and JSON machine values do not change with display language.
- Resource checks run before scanning. Adjustable limits offer keep, stop, or increase and continue, applying only to the current scan unless explicitly saved. Ordinary text and scripts allow bounded 1/2/4-task concurrency; complex containers remain sequential.
- Small-window and scaling layouts improve, and remediation previews show exact actions and exclusions. Quarantine of read-only malicious sources works when the required access is already held, while file identity, occupancy and administrator plan checks remain enforced.
- Verified 0.2.0 upgrades can tighten permissions for only four qualifying fixed, empty state directories, with protected progress records for interruption recovery. Existing data, unknown provenance and unsuitable permissions remain preserved and explained.

See the [English quick start](QUICKSTART.en.md) and [Chinese overview](../README.md).

## Evidence and its scope

The published [ACCEPTANCE-SUMMARY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/ACCEPTANCE-SUMMARY.json) contains the detailed results. Counts across builds and stages must not be combined into one full rerun.

| Evidence | Completed checks | Scope |
| --- | --- | --- |
| Revision 2 archived source | 56 maintenance and 43 machine-state checks; zero failures or skips | Newly run installer checks |
| Revision 2 final signed package | Windows 10 build 19045 and Windows 11 build 26200 each pass 56 maintenance checks; reproduce the old failure, then pass short-path upgrade and normal-path reinstall, covering Chinese and English installation execution | Each verifies 531 payload files, three exact legacy-file fixtures, retained records and permissions, four standard-user scan/export/cancellation checks, and reboot verification |
| Actual early installation | Corrected production read-only preflight passes with unchanged bytes and ACLs | No host upgrade; VM legacy-layout fixtures and actual-host read-only evidence are distinct, not a complete early-build reconstruction |
| Full product baseline | 2,358 passed, zero failed or skipped | Retained for the seven identical product binaries; not rerun for this installer revision |
| Candidate09 and preview.1 | Recorded checks: Windows 10 GUI 152; Windows 11 GUI 35; original malicious ZIP static checks 89; Scratch GUI and records 208; installer wizard evidence 34; all failure counts zero | Original candidate/stage identities remain; preview.1 has separate post-signing installation and standard-user evidence |
| Earlier candidates | Infection, quarantine, same-version Steam restoration and reboot records preserved | Not relabeled as full infection/recovery repeats on candidate09, preview.1 or revision 2 |

Setup, the seven product files and both actual installed uninstallers have verified signatures. Historical test-harness issues and corrections remain recorded in the acceptance summary; only the final successfully executed bounded workflows are marked passed.

## Retained limits

- Basic scanning does not call AMSI. Its absence alone does not mark a scan incomplete; actual read, password, format, permission and resource gaps remain visible. Historical reports are not rewritten.
- ISO/DVD scanning is outside the support commitment. This round used individually hash-verified NTFS copies of three original malicious ZIPs. Two unexplained TianLai dependency tails retain Partial coverage.
- Physical multi-monitor testing and AMSI-provider health work remain paused. The conditional legacy migration notice was not visually observed, an accepted gap; migration behavior has separate tests.
- Raising limits does not bypass permissions, paths, identity checks or format limits, or authorize remediation. Successful actions and no-residual checks apply only to exact targets and do not establish whole-machine safety.
- No measured parallel speedup factor is claimed. Exact certificate/proxy configuration rules and real remediation acceptance remain subject to the [phase-three scope](EXACT-REMEDIATION-PHASE3.md); names alone do not authorize configuration removal.
- Normal exports contain no malware payloads or archive passwords. Saved cases cannot replay administrator authorization. Active quarantine records cannot be permanently deleted; only verified empty, fully rolled-back incidents can be removed.

## Published sources and history

- Current [English release notes](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-NOTES.en.md) / [Chinese release notes](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/RELEASE-NOTES.zh-CN.md), plus the identity and acceptance attachments above.
- [preview.1 release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.1): first self-signed publication, candidate09 and historical evidence provenance.
- [Changelog](../CHANGELOG.md), [implementation plan](PLAN-0.3.0.md), [earlier joint acceptance](JOINT-ACCEPTANCE-0.3.0.md) and [third-party notices](../THIRD-PARTY-NOTICES.md). Read historical statements about development, pending acceptance or missing installers in the context of their dates and build identities.
