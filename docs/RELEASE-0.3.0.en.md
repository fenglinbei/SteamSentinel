# SteamSentinel 0.3.0 release identity and acceptance index

Updated September 28, 2026. [简体中文](RELEASE-0.3.0.md)

Product **0.3.0** was publicly released on September 28, 2026 as [v0.3.0-preview.3 self-signed Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.3). This page records its release identity and acceptance scope. Rules are `2026.09.28.1`. The product and installer are fully rebuilt. Results from different builds, stages and test helpers remain separate; historical records are not rewritten as acceptance of this package.

## Download and provenance

| Field | Release identity |
| --- | --- |
| Release tag | `v0.3.0-preview.3` |
| Product / platform | `0.3.0` / Windows x64; installer minimum Windows 10 build 19041 |
| Rules / self-contained runtime | `2026.09.28.1` / `.NET 10.0.12` |
| Installer | `SteamSentinel-0.3.0-preview.3-selfsigned-setup.exe` |
| Installer SHA-256 | `33AE8B1B9A1C5C2E8B82F92210686FE9E525BF59415C89FD03F53E5C1DEA140B` |
| Clean build source commit | `67e507b744a88e072707ae3c6d2ebdf34f3e7429` |
| Build source tree | `7f533a585afa0cc08f81dd73dec4e27ffc530964` |
| Product build identity | `0.3.0+67e507b744a88e072707ae3c6d2ebdf34f3e7429.preview` |
| Payload / binary ZIP / source ZIP | 535 manifest entries / 536 files including the manifest / 410 files |
| Signing | `SELF-SIGNED-PREVIEW`; no public trust chain or timestamp |

Use the complete installer and check the [SHA-256 manifest](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/SteamSentinel-0.3.0-preview.3-selfsigned-RELEASE-SHA256.txt), [PUBLICATION-IDENTITY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/PUBLICATION-IDENTITY.json) and [RELEASE-METADATA.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/RELEASE-METADATA.json). A shared product version does not mean identical builds. Later main-branch documentation updates do not change this product source commit or build identity.

The certificate is `CN=fenglinbei`, SHA-1 fingerprint `3395882D18D66EFA1545C1FE6DD867EB004176D1`, expiring `2027-09-04 10:00:58 UTC`. Windows may report an untrusted publisher. `SIGNER.cer` contains only the public certificate and does not automatically modify system trust. Setup and all seven product files passed signature-integrity verification; installed uninstallers and VM acceptance are tracked separately below. See `SIGNING.txt` and [signing documentation](SIGNING.md).

## Rule correction 3

- General token co-occurrence becomes Medium/40 and review-only, without eligibility to quarantine a file or stop its host. Similar weak evidence in MSI declarations, shortcuts and Run history follows the same boundary. Associations derived only from weak file observations remain diagnostic.
- `.node` is compatible with valid Windows PE native modules; content and hashes remain checked. A historical-path-only match becomes a Low/20 observation. Names do not establish malicious identity.
- Exact malicious hashes, specific strong rules, bounded VPet family inspection and independent configuration evidence retain their own eligibility rules. Fresh exact malicious-hash evidence has an independent rule identity instead of reviving a retired weak rule.
- Evidence retains bounded fixed tokens, encodings and decoding-window positions, without arbitrary surrounding text or claims about execution order. The scanner does not run scripts, shortcuts or extracted programs to validate these tokens.
- Historical reports and cases retain their original text, scores and outcomes. The interface and new-plan entry points reject retired weak rules and retain exclusion reasons. Rescan the original scope after upgrading; neither upgrading nor rescanning automatically undoes previous actions.

Review-only is not proof of safety. General file quarantine still does not independently reclassify every finding as malicious inside the administrator Broker. This correction tightens interface, association and new-plan eligibility; it introduces neither privileged archive parsing nor complete report authenticity proof. See the [correction principles and boundaries](FALSE-POSITIVE-CORRECTION-0.3.0.en.md).

## Product capabilities

- Inspect the studied SmartPet, TianLai and Scratch original packages, core components and verified derived payloads. Preserve component relationships and per-file Steam HTML/CSS/JS and support-route evidence, with correct ZIP Chinese member names.
- Provide Simplified Chinese and English, saved per user for the next launch. Markdown and record bundles can use a separate export language; JSON machine values and original evidence do not change with display language.
- Resource checks and per-scan grants do not bypass permissions, paths, identity or format limits. Ordinary text and scripts use bounded 1/2/4-task concurrency according to actual CPU, memory and budgets. Complex containers remain sequential; no measured speedup factor is claimed.
- Retain exact remediation previews, exclusion reasons, occupancy and locked-handle identity checks, eligible read-only malicious-source quarantine and rollback that refuses to overwrite existing files.
- Retain revision 2's valid-short-path installation fix, exact legacy-icon migration and path diagnostics. Verified 0.2.0 upgrades tighten permissions only for qualifying fixed, empty directories; existing data and unknown provenance remain preserved.

See the [English quick start](QUICKSTART.en.md) and [Chinese overview](../README.md).

## Current acceptance and original failure records

The actual release attachment [ACCEPTANCE-SUMMARY.json](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/ACCEPTANCE-SUMMARY.json) provides detailed results. Counts from independent runs must not be combined into one full self-test.

| Evidence | Verified result | Scope |
| --- | --- | --- |
| Complete clean-source build | Native apphost, self-contained `.NET 10.0.12`: 2,469 passed, 0 failed, 0 skipped | Newly run for the source commit and Preview identity above |
| Windows CI for the same commit | [Run 36421041587](https://github.com/fenglinbei/SteamSentinel/actions/runs/36421041587): 2,469 passed, 0 failed, 0 skipped; build and formatting passed | Independent CI run with a `.ci` identity suffix; do not add its count to the native run |
| Fresh installer source checks | Maintenance 56 and machine state 43; 0 failed, 0 skipped | Newly run installer checks, separate from final-package VM acceptance |
| Signatures and package structure | Setup and seven product files pass signature-integrity checks; 535 manifest entries, 536 binary ZIP files, 410 source ZIP files | Self-signed, without public trust or a timestamp |
| Historical eligibility replay using final signed Core | All 3 direct retired weak findings across 3 reports blocked; independent configuration eligibility retained 1/1; original ZIPs unchanged 3/3 | Historical JSON only: no target-file reads, program execution or remediation plans. Public output contains aggregate counts only |
| Original Windows 10/11 standard-user helpers | each 3/4; the three successful scan/export checks per system remain recorded; cancellation did not pass | Outdated Stage display text prevented the helper from requesting cancellation. The original result is not relabeled 4/4 |
| Final-package Windows 10/11 baseline acceptance | **Windows 10 build 19045 and Windows 11 build 26200 each completed upgrade, same-version reinstall, 535 payload-entry checks, original-record/permission preservation and bilingual startup probes** | Original scan/export checks and independent cancellation probes remain distinct; startup probes are not a new visual GUI acceptance run |
| Final-package false-positive regression | Windows 10/11 each: 164 passed, 0 failed, 0 skipped | Bound to the final signed product; includes strong-rule and weak-evidence eligibility checks |
| Independent cancellation probes | **each system ran Simplified Chinese and English once; both triggered and completed cancellation with no new Worker temporary-directory leftovers** | Stable stage IDs trigger cancellation; report Simplified Chinese and English results per machine without replacing the old helper record |
| Original malicious ZIP static corpus | **all three original ZIPs completed static scanning, retaining all 15 expected strong rules and their eligibility; coverage is Complete / Partial / Complete, with unexplained TianLai dependency tails remaining Partial** | Only the scanning, detection and coverage actually checked; not a new infection, quarantine or recovery acceptance run |
| Final-package reboot verification | **each system rebooted once; the new boot, 535 payload entries, original records and permissions, and uninstaller identity were verified** | Record the actual system, build identity, language and verified scope |

## Historical installer fixes and acceptance

[Preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2) fixed legitimate Windows short names, such as `ADMINI~1`, that caused `Code=UnsafePath; Path=; Mode=Preflight`. Real handles and pinned parent directories preserve rejection of reparse redirection, hard links and untrusted writers. Early `Assets\App.ico` and `Assets\App.png` are retired only when both approved size and SHA-256 match; changed or unknown files remain preserved. For an older installer's short-path failure, close ordinary and administrator windows and use this complete package, without manually deleting files or weakening permissions. See [installation upgrade rules](INSTALLER-UPGRADE-0.3.0.md).

Preview.2 retained seven product binaries identical to preview.1 and the historical **2,358-check** full baseline; it did not repeat the full product self-test. Its new source checks were maintenance 56 and machine state 43, followed by Windows 10/11 installation workflows, 531 payload-file checks per machine, standard-user workflows and reboot verification. Its source snapshot was `5878b6139caaf7cab90c647eb92c9c5d8a6febc6`, while executables retained the original dirty Preview identity. These remain historical facts; the present 2,469-check full run and clean build do not reuse that identity. See the original [preview.2 acceptance summary](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.2/ACCEPTANCE-SUMMARY.json).

Candidate09 and preview.1 records retain their original candidate or stage identities: Windows 10 GUI 152, Windows 11 GUI 35, original malicious ZIP static checks 89, Scratch GUI/records 208 and installer wizard evidence 34. Earlier infection, quarantine, same-version Steam restoration and reboot records also retain their original identities; none becomes a repeat of that whole workflow on this package. Actual-host read-only preflight, VM legacy-layout fixtures and a complete reconstruction of an earlier build are distinct evidence.

## Retained limits

- Basic scanning does not call AMSI. Its absence alone does not mark a scan incomplete; actual read, password, format, permission and resource gaps remain visible. Historical reports are not rewritten.
- ISO/DVD scanning is outside the support commitment. Static original-archive checks and historical JSON eligibility replay are separate. No claim is made that the original DLLs mentioned by the three historical reports were individually proven safe. Two unexplained TianLai dependency tails retain Partial coverage.
- Physical multi-monitor testing and AMSI-provider health work remain paused. The conditional legacy migration notice was not visually observed, an accepted gap; migration behavior has separate tests.
- Action completion and exact-target verification do not establish whole-machine safety. Exact certificate/proxy rules and real remediation remain subject to the [phase-three scope](EXACT-REMEDIATION-PHASE3.md); names alone do not authorize removal.
- Normal exports contain no malicious payloads or archive passwords. Historical cases cannot directly replay administrator authorization. Active quarantine records cannot be permanently deleted; only verified empty, fully rolled-back incidents can be removed.

## Sources

- Release attachments: [Bilingual release notes](https://github.com/fenglinbei/SteamSentinel/releases/download/v0.3.0-preview.3/RELEASE-NOTES.md), and the identity and acceptance attachments above.
- [Preview.1](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.1), [preview.2](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.2), [changelog](../CHANGELOG.md), [implementation plan](PLAN-0.3.0.md), [earlier joint acceptance](JOINT-ACCEPTANCE-0.3.0.md), [third-party notices](../THIRD-PARTY-NOTICES.md). Read historical development or pending-acceptance statements in the context of their dates and build identities.
