# SteamSentinel 0.3.0 — English quick start

SteamSentinel is a local Windows tool for inspecting known fake Steam alert malware, related Workshop content, mods and plugins, and supported Steam modifications. It can quarantine precisely selected eligible files and retain records for review and rollback.

Product version remains **0.3.0**. It was publicly released on September 28, 2026 as [v0.3.0-preview.3 self-signed Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.3), with rules `2026.09.28.1`. The product and installer are fully rebuilt from clean commit `67e507b744a88e072707ae3c6d2ebdf34f3e7429`. The product build identity is `0.3.0+67e507b744a88e072707ae3c6d2ebdf34f3e7429.preview`; it does not reuse preview.2's original dirty binaries.

The new native full self-test passed **2,469 checks**; Windows CI for the same commit separately passed **2,469**. Fresh installer maintenance **56** and machine-state **43** checks passed, all with zero failures or skips. These independent counts are not added together. Final-package Windows 10/11, static corpus and reboot acceptance: **each system passed 164 false-positive checks, upgrade and same-version reinstall, 535 payload-entry checks, bilingual startup probes, the original three scan/export checks plus independent bilingual cancellation, and one reboot verification; three original ZIPs retained all 15 expected strong rules with Complete / Partial / Complete coverage**. See the [release identity and acceptance index](RELEASE-0.3.0.en.md) for verified results and their scope, including both original Windows 10/11 helpers' 3/4 results and separate bilingual cancellation probes. Preview.2's 2,358-check baseline remains historical evidence.

General URLs and command tokens appearing together are now review-only and do not authorize quarantine or stopping a host. Exact malicious hashes, specific strong rules, bounded VPet family inspection and independent configuration evidence retain their own rules. Historical reports and cases are not rewritten. Upgrade and rescan the original scope; review-only is not proof of safety, and upgrading does not automatically undo prior actions. See the [false-positive correction](FALSE-POSITIVE-CORRECTION-0.3.0.en.md).

The certificate is self-signed, with no publicly trusted chain or timestamp; Windows may report an untrusted publisher. Physical multi-monitor tests remain paused. The conditional legacy migration notice retains an accepted visual coverage gap, and earlier infection/recovery results retain their original candidate identities.

The optional system AMSI enhancement is currently paused: its controls are hidden and scans do not initialize or call that engine. Its absence does not mark a baseline scan as incomplete, and Norton is not required. Historical reports keep their original findings and coverage. Actual file-read, password, format or missing-volume failures still produce inspection gaps.

## Install or upgrade

Use the complete installer from the [v0.3.0-preview.3 release page](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.3). Check its identity and SHA-256 against `PUBLICATION-IDENTITY.json`, `RELEASE-METADATA.json` and the version-prefixed `RELEASE-SHA256.txt`. Read `SIGNING.txt` for signing status. Close both ordinary and administrator application windows before upgrading, and install the whole package rather than replacing an individual EXE or DLL. The older installer's `Code=UnsafePath; Path=; Mode=Preflight` short-path issue was fixed in revision 2 and that fix is retained; do not manually delete old files or weaken directory permissions.

The installer supports English and Simplified Chinese and uses the same installation location and upgrade identity for both. Its language does not change another Windows user's application preference. Administrator remediation requires a protected, intact installation in Program Files. The portable package can scan and export reports, but administrator remediation and quarantine rollback are unavailable there.

## Choose the application language

Open **Language** (**语言 / Language** in Chinese), select Auto, 简体中文 or English, then select **Save language**. The setting applies on the next launch; the current window and running work keep their language. Auto follows the Windows user's display language, using Simplified Chinese for Chinese and English otherwise.

A new administrator window inherits the language currently displayed by the originating window. It does not overwrite the administrator account's saved preference. See [language settings and exports](LANGUAGE-SETTINGS-0.3.0.md) for details.

## Scan and read the results

1. Start with **Quick scan**, then use a full content scan for the relevant Steam libraries, Workshop content and installed mods. The quick scan does not inspect every disk.
2. Use **Scan file** or **Scan folder** for a specific download, archive or plugin. Review the actual scan scope, especially when Steam libraries or manually copied mods are outside the usual folders.
3. Read both the finding and the coverage information. A completed scan operation can still have content that was not checked.
4. Open a finding's details to review the exact target, evidence, reason and suggested next step before selecting an action.

| Result | Meaning |
| --- | --- |
| Confirmed malicious | The available evidence identifies a known malicious target. Check its exact identity and location. |
| Review required | The observation needs assessment; it is not automatically proof of infection. |
| Some content was not checked / Partial | Password failures, unsupported structures, missing volumes, limits or unavailable inspection components left a gap. |
| No known threats found | No known threat was detected in the checked scope; unchecked or unknown content may remain. |
| Selected actions completed | The selected operations completed. Review verification results and any remaining findings separately. |

An archive containing a malicious member does not by itself prove that the computer executed it. A suspicious filename, third-party mod or unsigned library alone does not establish maliciousness.

If an archive is encrypted, the password dialog lets you limit reuse to the current layer, the current outer file and its nested content, or the current scan. You can skip it and later retry undecrypted content. Skipping retains an inspection gap. Archive passwords are not stored in reports or passed on the command line.

## Scan limits and performance

The application estimates available memory and temporary disk space before scanning. When an adjustable limit is reached, review the current limit, proposed increase and resource risks. Choose **Keep limits**, **Stop scan**, or **Increase and continue**. Approval applies only to the current scan unless you explicitly select the option to save it for future scans in that mode. Closing the dialog keeps the limit. Waiting for your decision does not consume the scan time budget.

If capacity is insufficient or unknown, approval is disabled. You can free resources and select **Recheck resources**. Estimates cover the blocked operation or the next bounded portion of work; changing system load and unknown archive contents mean they cannot guarantee that all remaining work will finish. Permission, path, integrity and supported-format checks continue to apply. Skipped content remains visible as an inspection gap.

In scan limit settings, **Low impact** uses one file task, **Automatic** allows up to two, and **High throughput** allows up to four. The scanner reduces concurrency when resources, disk latency or remaining budgets require it. Parallel scanning covers recognized ordinary text and script files up to 8 MiB each. Large files, archives, volume groups, password groups, native installer parsing and recovery output remain sequential. Actual gains depend on the input; these options do not weaken detection rules. The report records actual peak concurrency and resource decisions.

New reports record AMSI as disabled while the enhancement is paused. Older reports may retain AMSI failure evidence and **Partial** coverage; they are not rewritten. Running the main window as administrator does not remove the worker's low-privilege boundary.

## Review, quarantine and rescan

Eligible known malicious findings may be selected by default. Heuristic findings require independent strong evidence and remediation eligibility before they can be selected manually, and are not preselected. General token co-occurrence remains review-only and cannot be selected for quarantine. Review the action preview, paths, hashes and reasons, and close affected Steam or game processes when requested. A process or file changing between scanning and execution can cause an action to be refused; inspect the result and scan again.

A standard Windows account must open an administrator window, provide administrator credentials in the Windows prompt, then scan again there. The original report, selection and passwords are not transferred across accounts. Include the original user's Steam and Workshop folders if the administrator's automatically discovered scope differs.

Quarantining a malicious plugin does not repair all previously modified Steam files. After addressing the identified source and reviewing the affected Steam files, restore Steam through its official client or installer, then restart Windows and rescan the original scope. The laboratory's same-version offline restoration is a test procedure; it is not evidence that the product automatically repairs every Steam installation.

Workshop subscriptions or another local copy can reinstall an unwanted mod. Review the exact Workshop identity and subscription yourself; SteamSentinel does not silently unsubscribe all mods. Local cleanup also cannot revoke credentials that may already have been exposed.

## Reports, quarantine and rollback

**Export report** supports human-readable reports and JSON evidence. Markdown and record bundles default to the current interface language and allow a language for that export only. Exporting the same report object in another language does not change its machine-readable JSON. Original evidence, operating-system errors and older free-text records can retain their source language.

Normal reports contain metadata and use the application's redaction rules; they do not include malware samples or archive passwords. Review an export before sharing it, because paths and original evidence can still contain identifying details.

Use **Quarantine & rollback** only after reviewing why the item was quarantined. Restoring malware can make it runnable again. Rollback refuses to overwrite a conflicting destination and records its outcome. This version does not permanently delete active quarantine records; only verified empty, fully rolled-back incidents can be removed. Do not restore malware merely to make an incident deletable.

Uninstalling the application retains quarantine and machine records. Keep those records until the investigation and any necessary recovery are complete.

## Data and project information

- User settings and reports: `%LOCALAPPDATA%\SteamSentinel`.
- Restricted worker temporary data: `%USERPROFILE%\AppData\LocalLow\SteamSentinel`.
- Machine quarantine and results: `%PROGRAMDATA%\SteamSentinel\Quarantine` and `%PROGRAMDATA%\SteamSentinel\Results`.
- [Release identity and acceptance index](RELEASE-0.3.0.en.md), [Chinese overview and build instructions](../README.md), [historical implementation plan](PLAN-0.3.0.md), [signing](SIGNING.md), [third-party notices](../THIRD-PARTY-NOTICES.md), [Apache 2.0 license](../LICENSE).
