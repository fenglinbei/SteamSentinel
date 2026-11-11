# SteamSentinel 0.3.5 local preview — English quick start

SteamSentinel is a local Windows tool for inspecting known fake Steam alert malware, related Workshop content, mods and plugins, and supported Steam modifications. It can quarantine precisely selected eligible files and retain records for review and rollback.

Source version is **0.3.5**, with rules `2026.11.10.1`. This is a local preview with conservative/aggressive handling modes, exact Steam configuration repair, and verification of hosts that load a known malicious embedded payload. It has not been published externally. The older public detection release remains [v0.3.3-preview.1](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.3-preview.1); it does not contain these changes. Updated 2026-11-11; [简体中文](../README.md), [local preview notes](RELEASE-0.3.5-preview.md).

The application starts in **Conservative** mode. **Aggressive** mode lets you select eligible physical files that remain suspicious rather than confirmed malware. Switching modes clears the current selections, and newly eligible risk findings are not preselected. The original rule, score, classification and evidence remain unchanged. Review all user-selected actions before confirming; false positives can affect legitimate software or extensions.

Revision 5 uses one complete package with a native startup check. It verifies the payload and probes the actual hosts before starting the application. Only a confirmed, known CET initialization failure allows one compatibility attempt. Standard hosts retain CET; compatibility hosts opt out for this application without changing system security settings. Unknown startup errors stop and produce a local report instead of replaying business operations. Managed errors also provide a report path when available; reports are not uploaded automatically.

Version 0.3.3 detects the known SteamAlert mod downloader, resident host and independent core DLL. Run a full scan of the installed mods and resident files. Review behavior-only matches and affected Steam UI scripts before repairing the client. [Current release notes](RELEASE-0.3.3-preview.1.en.md).

Version 0.3.2 lets eligible exact files enter preview from any ordinary local directory, including unprotected ordinary files in Windows or Program Files. Results distinguish confirmation, sensitive-location verification and blocked items. Scope information is integrated into the existing confirmation window, with no extra authorization dialog and no increase in ordinary per-batch confirmations. See the [0.3.2 scope notes](RELEASE-0.3.2-preview.1.en.md).

New cases use multipart storage. Export a full record bundle and retain the entire case directory before downgrading to 0.3.0. This release includes static detection results for SteamAlert samples and clean mod controls. The scope authorization and large scan test records are available on the [0.3.2 release page](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.2-preview.1).

Revision 4's recovery behavior is retained: startup checks old operations, and a confirmed finished operation no longer blocks a new scan and plan. Historical unknown outcomes remain unknown. Disabled controls explain the reason and offer **Check and continue**, **Scan again**, or **View records**. You do not need to delete cases or edit configuration, and saved plans are never replayed.

Revision 3's classification corrections remain: general URLs and command tokens do not become confirmed malware. Conservative mode keeps those findings for review; Aggressive mode records a separate user choice when an eligible exact file is selected. Exact malicious hashes, strong rules and independent configuration evidence retain their eligibility. Upgrade and rescan the original scope. Review-only does not prove safety. Read the delivered package's signing information; a self-signed certificate without public trust or a timestamp can still produce an untrusted-publisher warning.

The optional system AMSI enhancement is currently paused: its controls are hidden and scans do not initialize or call that engine. Its absence does not mark a baseline scan as incomplete, and Norton is not required. Historical reports keep their original findings and coverage. Actual file-read, password, format or missing-volume failures still produce inspection gaps.

## Install or upgrade

Use the complete installer supplied for this 0.3.5 local preview. Check `VERSION.txt`, `SIGNING.txt`, the SHA-256 manifest and build records before installing. The [older public release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.3-preview.1) remains separately available. Close both ordinary and administrator application windows before upgrading, and install the whole package without replacing individual EXEs/DLLs or mixing hosts from different packages. Do not manually delete old files or weaken directory permissions.

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

Use the default **Conservative** mode for evidence-backed cleanup and configuration repair. Eligible known malicious findings within the existing automatic scope may be selected by default. **Confirmation needed**, **Sensitive location · verification needed**, and heuristic findings remain initially unselected. **Blocked** items cannot be selected.

Select **Aggressive** only when you want to act on suspicious physical files that meet the identity and safety checks. Changing mode clears every selection. Select the desired rows again and inspect actions marked **User-selected action**. Direct Run/RunOnce entries and running processes that are bound to the selected file may be included in the same preview. A filename such as `361` alone does not authorize startup deletion. These choices do not turn the scan findings into confirmed malware, and missing or incomplete evidence is not replaced by a higher displayed score.

Review every batch's exact targets, impacts and excluded items in the existing preview. Scope authorization adds no separate dialog; the ordinary administrator confirmation for each batch remains. Windows UAC follows the actual elevation flow, so this does not mean one confirmation or one UAC prompt for the entire task. Consent covers only listed exact files and the other listed actions, not a whole directory or future plans. Close affected Steam or game processes when requested.

Windows Resource Protection files, critical system paths, the tool's own files/state, network/device paths, reparse points and files with multiple hard links remain blocked. Expanded-scope quarantine also refuses files with additional data streams or special metadata it cannot fully restore, or when required original security information cannot be verified. Changing a file or its parent directory after inspection can cause refusal; inspect the result and scan again. The application does not provide automatic system repair or an offline remediation queue.

A standard Windows account must open an administrator window, provide administrator credentials in the Windows prompt, then scan again there. The original report, selection and passwords are not transferred across accounts. Include the original user's Steam and Workshop folders if the administrator's automatically discovered scope differs.

Before Steam configuration or script repair, fully exit Steam and Steam Web Helper. Supported `steam.cfg` repairs clear only enabled update suppression or forced offline settings, including `BootStrapperInhibitV3`, while retaining other settings, comments and supported encoding. The Steam-root `.cef-enable-remote-debugging` marker can be backed up and removed. Direct Run commands and supported shortcuts are changed only after their target is verified as an installed `Steam.exe`; only the complete `-cef-enable-debugging` argument is removed. Legitimate extensions can use these settings, so their presence is not proof of malware.

A physical host can now qualify for conservative quarantine when independent verification follows its entry point through the complete bytes of a known malicious embedded Core, assembly loading and the payload entry-point call. This confirms the embedded payload and its loading chain, not an exact known hash for the whole host. Archive members can report this strong evidence, but the administrator execution component does not yet reverify the outer container for this rule, so Conservative mode keeps them for review. In Aggressive mode, the user can select the physical archive if it has a bound outer-file hash and passes the safety checks. Behavior-only 90-point findings retain their suspicious classification.

Confirmed Steam script injection tails can be precisely repaired with a backup and verification of the resulting hash. Quarantining a plugin or restarting Steam does not guarantee that every modified client file is restored. Unresolved suspicious downloaders, hosts or core components are reported as possible sources of future modifications even if a script repair succeeds. Restore other unsupported changes through a verified Steam source and rescan the original scope after restarting. The product does not claim that static or laboratory checks establish recovery of every real infected system.

Workshop subscriptions or another local copy can reinstall an unwanted mod. Review the exact Workshop identity and subscription yourself; SteamSentinel does not silently unsubscribe all mods. Local cleanup also cannot revoke credentials that may already have been exposed.

## Reports, quarantine and rollback

**Export report** supports human-readable reports and JSON evidence. Markdown and record bundles default to the current interface language and allow a language for that export only. Exporting the same report object in another language does not change its machine-readable JSON. Original evidence, operating-system errors and older free-text records can retain their source language.

Cases, plan JSON and record bundles retain the actual handling mode and user-selected-risk action markers. Ordinary scan JSON and Markdown continue to describe the original detection evidence; they do not relabel a user choice as a malicious finding.

Normal reports contain metadata and use the application's redaction rules; they do not include malware samples or archive passwords. Review an export before sharing it, because paths and original evidence can still contain identifying details.

Use **Quarantine & rollback** only after reviewing why the item was quarantined. Restoring malware can make it runnable again. Expanded-scope restoration requires fresh confirmation against a verified, trusted quarantine manifest, then checks the copy's hash, original parent-directory identity and saved restoration information. It restores supported permissions, attributes and times, refuses to overwrite an existing destination, and retains the quarantine copy when verification fails. Configuration rollback also refuses to overwrite later changes. Stopping a process cannot restore its unsaved state. Old reports and saved plans do not grant a new handling mode or replay automatically; rescan and confirm a new plan for new remediation.

This version does not permanently delete active quarantine records; only verified empty, fully rolled-back incidents can be removed. Do not restore malware merely to make an incident deletable.

Uninstalling the application retains quarantine and machine records. Keep those records until the investigation and any necessary recovery are complete.

## Data and project information

- User settings and reports: `%LOCALAPPDATA%\SteamSentinel`.
- Restricted worker temporary data: `%USERPROFILE%\AppData\LocalLow\SteamSentinel`.
- Machine quarantine and results: `%PROGRAMDATA%\SteamSentinel\Quarantine` and `%PROGRAMDATA%\SteamSentinel\Results`.
- [Local preview notes](RELEASE-0.3.5-preview.md), [older public release identity and acceptance](RELEASE-0.3.3-preview.1.en.md), [Chinese overview and build instructions](../README.md), [historical implementation plan](PLAN-0.3.0.md), [signing](SIGNING.md), [third-party notices](../THIRD-PARTY-NOTICES.md), [Apache 2.0 license](../LICENSE).
