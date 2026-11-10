# SteamSentinel 0.3.2: exact file scope and confirmation

2026-11-10. [简体中文](RELEASE-0.3.2-preview.1.md)

Product version **0.3.2**, tag `v0.3.2-preview.1`, rules `2026.09.28.1`. This remains a self-signed Pre-release using `CN=fenglinbei`; existing stable/latest designations remain unchanged. Download the complete installer from the [release page](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.2-preview.1), close ordinary and administrator windows, upgrade, and rescan the scope you intend to address.

## File scope and workflow

- Exact files meeting the existing evidence and remediation requirements can enter preview from any ordinary local directory. This includes ordinary files in Windows or Program Files that pass protection checks. A location outside the old automatic scope no longer prevents selection by itself. Detection rules are unchanged, and weak evidence does not become sufficient for remediation.
- The results list shows **Confirmation needed**, **Sensitive location · verification needed**, or **Blocked** before preparation. Ready, confirmation, verification and blocked counts remain separate. Confirmation and verification items are initially unselected; select them individually or through **Select all**. Blocked items cannot be selected.
- Preview retains the complete action list for every batch, exact targets and omitted-item reasons. Scope and sensitive-location impacts appear in the existing confirmation area. Quarantining an unprotected file in a Windows or application directory can still affect Windows or applications.
- **No extra scope-authorization dialog is added.** The existing application preview and ordinary administrator confirmation for each batch remain. Scope authorization does not increase those per-batch confirmation counts. Windows UAC still depends on the account, elevation state and execution flow; this is not a promise of one confirmation or one UAC prompt for the whole task.
- Confirmation applies only to the exact files and other actions listed in the current plan. It does not authorize an entire directory, neighboring files, future scans or another plan. The administrator execution process independently checks the plan, content hashes, file identities and parent-directory identities. A selection or request marker in a plan does not grant authorization by itself.

General token co-occurrence, retired weak rules and insufficient evidence remain review-only. Directory, process, service, registry, task and configuration actions retain their own eligibility and dependency requirements. This release adds no recursive directory-remediation permission.

## Conditions that still block operations

Windows Resource Protection (WRP) files, critical system paths, the tool's own programs and its state directories remain protected. UNC network paths, device paths, reparse points and redirected paths are outside this ordinary-local-file scope. Multiple hard links, changed content or a changed file or parent-directory identity cause the affected operation to be refused.

Expanded-scope quarantine must capture and verify the original security information, attributes and times needed for restoration. Additional data streams and special metadata that this version cannot fully restore, including encryption, compression and sparse attributes, block remediation. Unreadable or unverifiable required restoration information also stops the operation. Confirmation cannot bypass file permissions, system protection or these restoration requirements. Blocking reasons and incomplete outcomes remain recorded rather than becoming successful results.

Automatic system repair and an offline remediation queue are not implemented. Use Windows or the application's official recovery tools to repair damaged system or application components.

## Restoration and older records

Restoring an expanded-scope file requires fresh confirmation. The administrator execution process uses only a verified, trusted manifest from protected quarantine storage. It checks the quarantined copy's hash, original target, parent-directory identity and saved restoration metadata. Paths in ordinary reports cannot grant restoration authority. An existing destination is never overwritten. Missing information, changed identities or failed verification preserve the quarantine copy. Supported restoration also reapplies the recorded security information, attributes, creation time and modification time.

Older reports, cases and plans remain compatible. Upgrading does not grant expanded scope to them or replay saved plans. Rescan and confirm a new plan. Historical risk, incomplete findings and unknown outcomes are not rewritten as safe or successful.

The 0.3.1 fixes for diagnostic counting, approved budgets and multipart case persistence remain. Version 0.3.0 cannot read newly saved multipart cases; export a complete record bundle and retain the entire case directory before downgrading. See the [0.3.1 compatibility notes](RELEASE-0.3.1-preview.1.en.md). Unified startup, the restricted worker and existing remediation recovery behavior remain in place.

## Regression and release verification

Use the final `SCOPE-AUTHORIZATION-RESULTS.json` attachment to check exact scope authorization, sensitive locations, refusal paths, cancellation, changed identities, quarantine/restoration, older-data compatibility and bilingual UI coverage. Use `LARGE-SCAN-RESULTS.json` for the final worker's large harmless-file scan and save, reload, update and export of that same report. Actual coverage, pass/failure counts, skipped checks and binary identities come from those attachments; results not yet run are not prefilled here.

Use `PUBLICATION-IDENTITY.json`, `RELEASE-METADATA.json`, `ACCEPTANCE-SUMMARY.json` and the version-prefixed `RELEASE-SHA256.txt` for exact source commit/tree, build identity, signing and asset hashes. Full self-tests, unified startup, worker firewall contracts and installer maintenance/state tests report their results separately. Independent counts are not added together as one full suite, and older results are not treated as this release's acceptance evidence.

Harmless fixtures and large scans do not establish infected-machine cleanup, reboot recovery or installation behavior on every Windows environment. Any revalidation of legacy CET hardware, Windows 10/11 installer UI, physical multi-monitor behavior or external security review must be identified in the current acceptance attachments. This self-signed package has no publicly trusted certificate chain or timestamp; Windows may still warn about the publisher. Installation does not automatically change system certificate trust. Earlier startup compatibility boundaries are documented in [revision 5](RELEASE-0.3.0-preview.5.en.md).
