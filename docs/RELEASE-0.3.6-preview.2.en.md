# SteamSentinel 0.3.6 — Watchdog cleanup and verification fixes

Release tag: `v0.3.6-preview.2`. Embedded rules: `2026.11.17.1`. This preview combines PowerShell watchdog and temporary CMD updater cleanup with the findings UI update, and addresses firewall verification timeouts and hidden failure details reported during static sample quarantine.

## Corrections

- Program firewall verification narrows the provider query using the generated rule name, then checks its exact name and all application, direction, block action, port, address, service, interface and profile conditions. This action has a bounded 15-second observation timeout; other actions retain four seconds and the second pass retains its overall 20-second budget. Case reverification uses the same firewall-specific limit. Timeouts, cancellation, read failures and mismatched state still block dependent cleanup.
- Target summaries retain the execution or first-pass verification failure responsible for skipped actions. Copyable records include the selected target, its prerequisites, both observations and run-level errors. A later observation cannot hide an earlier failure.
- If every selected content root was skipped, the UI explicitly says that the selected paths were not inspected and opens the coverage explanation. Junctions and other reparse paths remain rejected; select the physical directory to scan it.
- Deterministic network LinkInfo shortcut fixtures keep local and Windows CI test counts consistent while retaining real Windows IDList checks.

## Updater cleanup and findings

Reviewed hashes cover the new resident, embedded Core, watchdog, updater and launcher, including scripts with and without a UTF-8 BOM and confirmed update copies. Confirmed installation scopes include `%ProgramData%\SteamAlertUpdater`, the resident's `Updater` directory, fixed caches and `.new.exe`, `.old` and `.bak` copies. Downloaded samples alone cannot authorize cleanup of installed components.

The approved chain stops the precisely bound watchdog, child script and CMD instances, removes bound startup entries, stops the resident, then quarantines scripts and confirmed resident/update copies. Each action rechecks bytes, commands, process identity and related state. Replacement instances, unknown files or unreadable state stop further cleanup. System interpreters and unrelated normal scripts remain protected.

Findings separate priority items from reference information. Plain format mismatches are collapsed by default, scores appear in details, and selecting priority items excludes collapsed reference items. Conservative/aggressive modes and Steam script/configuration repair remain available.

## Upgrade and validation

Close the application and administrator window before installing the complete package. Do not mix binaries from different builds. Rescan the original scope and review a new plan after upgrading; saved plans are never replayed. A successful firewall command does not mean its effective conditions passed verification, and a skipped quarantine does not mean a file was isolated.

The release attachments bind the source identity, full self-test, watchdog/UI checks and SHA-256 inventory to the final build. Tests use inert fixtures and static sample bytes without executing malware or contacting sample servers. Retesting on the reporting machine, actual infected-host cleanup, reboot and the fifteen-minute updater cycle remain separate acceptance work.

This is a self-signed preview without a publicly trusted certificate chain. It does not import certificates or modify system trust. The earlier `preview.1` tag remains a separate test snapshot; this public release uses `preview.2` and its own attachments.
