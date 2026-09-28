# 0.3.0 correction for findings based on weak evidence

Updated September 28, 2026. [简体中文](FALSE-POSITIVE-CORRECTION-0.3.0.md).

This page explains the correction's scope. It does not assert that a candidate installer has completed acceptance or been published. See the [0.3.0 release index](RELEASE-0.3.0.en.md) for published identities, actual acceptance results and release status.

## Why this changes

Normal application resources, help text and libraries can contain URLs, verification prompts and command names. The previous general script rule accumulated these tokens across an entire file, presenting unrelated strings as a high-risk deployment chain eligible for quarantine. Their presence does not prove downloading, execution or malicious behavior. Script-related strings in a DLL do not make the entire DLL a script.

## Scope

- General token co-occurrence becomes a **Medium, review-only** finding, using `HEUR-SCRIPT-TOKEN-COOCCURRENCE` and the stable reason `ScriptTokenCooccurrenceOnly`. It does not authorize file quarantine.
- Similar tokens in MSI declarations, shortcut targets and arguments, and Run history remain observations. Static declarations and historical text do not prove execution or grant remediation eligibility.
- Process or module associations supported only by weak file observations remain diagnostic information. They do not identify a normal host as loading confirmed malware or authorize stopping that host.
- `.node` is recognized as a conventional extension for a valid Windows PE native module. Content, hashes and other risks remain checked; this is not a blanket trust rule for `.node` files.
- A historical dropped-file path without an exact malicious-hash match becomes a Low path observation. Matching names do not establish matching malicious identities.

Exact malicious hashes, established specific strong patterns, bounded VPet family inspection and independent configuration evidence keep their separate rules. A fresh exact malicious-hash match receives its own evidence identity instead of reviving a retired weak rule. Unknown VPet family structures retain their existing review-only boundary.

## Evidence and older reports

Co-occurrence evidence retains bounded fixed tokens, encoding and decoding-window starting positions, without copying arbitrary surrounding text. Window positions are not exact token byte offsets. Matches after bounded literal joining or Base64 decoding are identified as normalized observations. None of this proves control flow, data flow or execution order. The scanner does not run scripts, shortcuts or extracted programs to validate these tokens.

Historical reports and cases retain their original text, scores, timestamps and outcomes. The corrected interface and new-plan entry points reject retired weak rules even when older records marked them actionable or highly scored. Batch previews retain the reason for exclusion.

Use a version containing this correction to rescan the original scope and assess current file identities and eligibility. Keep earlier reports for comparison. Rescanning does not automatically restore quarantined files or undo prior actions. Review the original target and quarantine reason before using the existing rollback workflow.

## Administrator boundary

The correction tightens interface selection, association evidence and new-plan eligibility. The administrator Broker retains its existing plan binding, permitted scope, exact-path and hash checks, and locked-handle file operations.

General file quarantine does not independently reclassify every scan finding as malicious inside the administrator process. This correction adds no privileged archive parsing and does not claim complete report authenticity proof. Existing independent strong-content checks for processes and persistence entries keep their limited scope; they must not be described as covering all files and containers.

Review-only does not mean proven safe. Confirmed malicious content and genuine inspection gaps remain visible. See the [English quick start](QUICKSTART.en.md) for scanning, reports, quarantine and rollback.
