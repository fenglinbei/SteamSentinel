# SteamSentinel 0.3.0 compatibility revision 5

Updated: 2026-10-02. [简体中文](RELEASE-0.3.0-preview.5.md)

This revision is [v0.3.0-preview.5 self-signed Pre-release](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.0-preview.5). Product version remains **0.3.0**, with rules `2026.09.28.1`. It addresses an observed CET initialization failure on older Windows systems and adds local evidence for other startup and managed errors.

## Install and start

Close ordinary and administrator SteamSentinel windows, then upgrade with the complete `SteamSentinel-0.3.0-preview.5-selfsigned-setup.exe` from the release page. The shortcut, installation path and upgrade identity remain unchanged. There is one package; users do not choose separate standard and compatibility downloads. Do not replace individual EXEs, mix DLLs, or alter system protection settings.

The native bootstrap validates the complete payload before probing the actual hosts without entering business operations. Standard hosts retain CET. One compatibility attempt is allowed only when the probe has not acknowledged readiness and returns both the known CET fatal message and exit `0x80131506`. Compatibility hosts opt out of CET for this application; the remaining security boundaries stay intact. A policy that forces CET may still prevent startup.

Unknown exits, timeouts, excessive output, integrity failures and failed compatibility probes stop startup and produce a report. Business failures never replay a plan. Broker preflight rejection is distinguished from an actual business exit. Each launch probes again rather than relying on a persistent mode cache.

## Changes

- One package contains native entry points and two small hosts for each App, Broker and Worker role, sharing managed assemblies and `.NET 10.0.12`. The existing UAC flow is retained; both Broker hosts still require administrator privileges.
- Worker low-integrity tokens and Job Object limits are preserved. Setup creates inbound and outbound blocks for the Standard, Compat and legacy-alias paths: six rules total. It verifies their exact paths and complete blocking conditions, and uninstall removes those six reserved names.
- Package metadata paths beyond traditional `MAX_PATH` no longer produce false missing-file failures. Component-by-component reparse checks, complete manifest hashing and rejection of unlisted loadable files remain in place.
- Native startup failures and managed unknown errors generate bounded local reports. Managed reports retain available exception chains, stack traces and software/runtime identity while redacting common credentials and user-profile paths. Nothing is uploaded automatically; reporting failures cannot recursively report themselves.

See the [unified startup design](UNIFIED-STARTUP.md) for process boundaries and limitations. Earlier false-positive corrections, finished-operation recovery and the paused AMSI enhancement are retained.

## Reporting an error

Send the report path shown by the error message, together with the failure time, software version and operation being attempted. Review the report for local paths you do not want to share.

- Native startup reports: `%LOCALAPPDATA%\SteamSentinel\Logs\startup-*.txt`, with `%TEMP%\SteamSentinel-Startup-Reports` as a fallback.
- Managed errors: `%LOCALAPPDATA%\SteamSentinel\Logs\error-*.log`, with `%TEMP%\SteamSentinel-Error-Reports` as a fallback when needed.

If Windows prevents the native bootstrap itself from running, terminates the process, or prevents report creation, the external diagnostic script and Windows event logs may still be needed. An unknown error is not automatically attributed to CET.

## Identity and assets

| Item | This revision |
| --- | --- |
| Tag / product version | `v0.3.0-preview.5` / `0.3.0` |
| Platform / bundled runtime | Windows x64; minimum Windows 10 build 19041 / `.NET 10.0.12` |
| Rules | `2026.09.28.1` |
| Signing | `SELF-SIGNED-PREVIEW`; no public trust chain or timestamp |
| Commit, source tree, build identity and asset hashes | `PUBLICATION-IDENTITY.json`, `RELEASE-METADATA.json`, and version-prefixed `RELEASE-SHA256.txt` |

The certificate is self-signed as `CN=fenglinbei`; Windows may report an untrusted publisher. Check the actual fingerprint in `SIGNING.txt` and `SIGNER.cer`. The certificate contains only the public key and is not automatically trusted by the system. This is a prerelease, not a publicly trusted production release.

Assets include the complete installer, portable `win-x64.zip`, corresponding `source.zip`, identity/signing files, acceptance summary and machine-readable results. Verify the complete asset hashes and provenance. Portable operation remains subject to the existing restrictions: it cannot bypass Program Files, ACL or complete-payload checks to perform administrator remediation.

## Acceptance limits

The local preparation baseline passed **2,710** native self-tests, **30** unified-startup checks, **22** Worker-firewall contract checks, **56** installer-maintenance checks and **43** machine-state checks, each with zero failures and skips. Separate suites are not added together as one full regression run.

Publication requires a fresh build from a clean commit and reruns the gates. Final identity and actual counts are recorded in `ACCEPTANCE-SUMMARY.json`, `SELFTEST-RESULTS.json`, `UNIFIED-STARTUP-RESULTS.json`, `WORKER-FIREWALL-CONTRACT-RESULTS.json` and both `INSTALLER-*-RESULTS.json` files. The local dirty package is not a substitute for the published build's provenance.

Startup coverage includes actual published-host probes and synthetic failure scenarios. **Affected older Win10 CET hardware has not been retested. Synthetic failures verify selection behavior; they do not establish that all Win10 startup failures are fixed.** Firewall-contract tests use inert objects and do not prove effective policy on a target machine. Final-package Win10/Win11 installation, upgrade, uninstall and all six firewall rules still require independent retesting. Earlier machine, recovery, reboot and layout results retain their original build identities.

An external security audit remains outstanding. ISO/DVD scanning is outside the promised scope; baseline scanning does not call AMSI. Physical cross-monitor testing and existing coverage gaps remain as previously documented. See the [revision 4 index](RELEASE-0.3.0.en.md) and [changelog](../CHANGELOG.md) for historical evidence.
