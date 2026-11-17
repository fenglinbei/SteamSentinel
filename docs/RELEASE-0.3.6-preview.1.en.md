# SteamSentinel 0.3.6 — Watchdog cleanup and finding groups

Release tag: `v0.3.6-preview.1`. Embedded rules: `2026.11.17.1`. This version combines the updater-chain fix and findings UI update, including the Steam script repair, remediation modes and configuration repair previously delivered in local 0.3.4/0.3.5 previews.

## Updater-chain cleanup

Exact reviewed hashes cover the new resident, embedded Core, watchdog, updater and launcher, including both BOM and BOM-free scripts. Confirmed installations include bounded discovery of the ProgramData and resident updater directories, update cache and replacement/backup images. Offline sample copies do not authorize unrelated installed targets.

PowerShell and CMD instances are bound to the complete command, script evidence, system image bytes, PID and creation time. The administrator broker checks them again through a pinned process handle and stops only instances listed in the confirmed preview. System interpreter files are preserved.

Temporary `sa_update_<PID>.cmd` scripts require the complete reviewed replacement/restart/rollback template and independently verified malicious payload bytes. Names and template text alone remain review evidence. Script and payload leases remain held through the quarantine operation.

The broker reconstructs the cleanup order: watchdog, approved child interpreters, bound startup entries, resident processes, scripts and update copies, then resident files. Before each family action it checks the current chain again. Newly started instances, new components, unknown replacement files or unreadable state stop subsequent actions without expanding termination authority. Verification checks new PIDs and does not treat a deleted script as proof its interpreter has exited.

## Finding groups

The results page separates priority findings from reference information. Plain format differences are collapsed by default, scores appear in details, and stronger evidence remains prominent. Select-all applies to the priority list without silently selecting collapsed reference findings. Full reports, manual inspection, mode switching and incomplete-scan states remain available.

## Package and validation

Exit SteamSentinel and its administrator windows before installing the complete package. Do not mix old and new binaries. Verify the attached release metadata, self-test results, signing information and SHA-256 lists. Rescan before preparing cleanup; old plans are not replayed.

The regression suite covers parsing, benign interpreters, PID reuse, changed commands, new instances after preview, installation boundaries, component coverage and cleanup dependencies. The `--steamalert-watchdog-tests <output>` utility uses harmless fixtures. The explicit `--steamalert-watchdog-samples <output> <sample>` utility only reads a sample whose hash matches the reviewed payload.

Malware samples were inspected statically without execution or requests to their servers. Automated and static validation do not establish successful cleanup, reboot recovery or a full fifteen-minute observation period on an infected machine. Unrecognized variants remain subject to review or a blocked cleanup.

This is a self-signed Preview, without a publicly trusted certificate chain. It does not import trust certificates. The release attachments record the exact build identity, final test counts and package hashes.
