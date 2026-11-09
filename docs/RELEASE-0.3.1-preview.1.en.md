# SteamSentinel 0.3.1: large scans and case persistence

2026-11-09. [简体中文](RELEASE-0.3.1-preview.1.md)

Product version **0.3.1**, tag `v0.3.1-preview.1`, rules `2026.09.28.1`. This remains a self-signed pre-release using `CN=fenglinbei`. Download the complete installer from the [release page](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.1-preview.1), close normal and elevated windows, upgrade, and rescan previously incomplete scopes.

## Changes

- Count only the retained worker diagnostic snapshot when receiving report fragments. Replacements release the previous charge; rejected fragments do not alter report data or counters.
- Apply the configured report text budget and explicitly approved increases to the receiver. Worker-provided settings cannot grant additional capacity. Checkpoint and final diagnostics are checked against the producer budget before transmission. Refused or stopped requests preserve incomplete results.
- Persist complete large case JSON as bounded pieces of at most 8 MiB, with exact lengths and SHA-256 hashes. Commit a small manifest atomically after the pieces are durable; failed commits preserve the previous revision. Loading verifies structure, order, size, hashes and complete JSON.
- Bound the display-only case summary while preserving the full original evidence. Startup recovery reads plans/results without constructing large report objects, but still checks every piece. Saved plans remain ineligible for replay.
- Coordinate readers and writers through the case lock, and reclaim unreferenced pieces after a successful save. Failed initial saves clean only newly created, never-committed data; existing incomplete records and unrelated files are preserved.

## Compatibility and limits

Legacy inline cases remain readable and migrate when next saved. **Version 0.3.0 cannot read newly written multipart cases.** Export a complete record bundle and retain the entire case directory before downgrading; copying only `case.json` is insufficient. Exports still contain complete ordinary JSON and metadata, not internal storage references or scanned payloads.

The serialized case limit is **2 GiB**, in at most 256 pieces. This bounds untrusted input; it does not remove scan budgets or imply unlimited available resources. Message, frame, path, authorization and process containment checks remain in place. Existing report findings and incomplete states are unchanged.

The installer, unified startup, Low Integrity worker, Job Object, elevated Broker and remediation scope retain their established boundaries. No new automatic remediation targets are introduced.

## Verification

New regressions cover more than 100,000 fragments, actual serialized text beyond the old receiver limit, approved/refused budgets, cases with more than 100,000 nodes, save/load/update/export, malformed manifests, missing/corrupt pieces and failed commits. Release acceptance additionally requires the final worker to scan at least 60,000 generated harmless files, approve real resource requests, and persist, reload, update and export that same large report.

Use `PUBLICATION-IDENTITY.json`, `RELEASE-METADATA.json`, `ACCEPTANCE-SUMMARY.json` and the version-prefixed `RELEASE-SHA256.txt` for exact source, build and asset identities. `LARGE-SCAN-RESULTS.json` records the large real-worker acceptance separately. Full self-tests, unified startup, firewall contracts and installer maintenance/state tests have separate result files and counts.

The harmless-file corpus is not a new infected-machine cleanup or reboot validation. Windows 10/11 installer UI, affected legacy CET hardware, physical multi-monitor behavior and external security audit are not claimed as revalidated. This self-signed release has no publicly trusted certificate chain or timestamp; Windows may still warn about the publisher. Prior compatibility boundaries are documented in [revision 5](RELEASE-0.3.0-preview.5.en.md).
