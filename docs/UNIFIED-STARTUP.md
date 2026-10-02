# Unified Windows startup and local error reports

SteamSentinel ships one installation containing a native bootstrap, six small
managed apphosts, and one shared set of managed assemblies and .NET runtime files.
The public shortcut and installation identity remain unchanged.

## Startup contract

| Entry | Purpose |
| --- | --- |
| `SteamSentinel.exe` | Native UI bootstrap; checks the actual App and Worker hosts before business startup. |
| `SteamSentinel.Broker.exe` | Native Broker bootstrap, entered through the existing UAC `runas` flow. |
| `SteamSentinel.Standard.exe` / `.Compat.exe` | Both bind to `SteamSentinel.dll`. |
| `SteamSentinel.Broker.Standard.exe` / `.Compat.exe` | Both bind to `SteamSentinel.Broker.dll`; both retain `requireAdministrator`. |
| `SteamSentinel.ArchiveWorker.Standard.exe` / `.Compat.exe` | Both bind to `SteamSentinel.ArchiveWorker.dll`. |
| `SteamSentinel.ArchiveWorker.exe` | Standard alias retained for established tools and upgrade compatibility. |

The native bootstrap is compiled with a static C++ runtime and without the CET
compatibility flag. Standard managed hosts retain CET; compatibility hosts use
the SDK's supported CET opt-out. No host is patched on an end user's machine.
Signing and the package manifest are generated after all hosts are finalized.

The bootstrap verifies `SHA256SUMS.txt`, its required entries, every listed file,
and unexpected loadable files before probing. Reparse paths, duplicate/traversal
manifest entries and modified payloads are rejected. The sole unlisted EXE
exception is Inno Setup's root-level `unins000.exe`, matching the managed verifier.
The existing Program Files ACL and complete installation checks still run before
privileged business operations; a compatibility preference never authorizes one.

The actual target host receives `--startup-probe <32-hex-nonce>`. After CLR
initialization, and before WPF, settings, plans or scans, it emits exactly:

```text
STEAMSENTINEL_STARTUP_READY/1|app-or-broker-or-worker|standard-or-compat|nonce
```

The native probe has a 20-second deadline, bounded stdout/stderr, a private handle
allowlist and a kill-on-close job. Host tracing is enabled only in that probe's
environment and captured in its private stderr pipe. The real application keeps
the original environment.

Only the known CET fatal message together with exit `0x80131506`, no readiness
acknowledgment, no timeout and no output overflow allows one compatibility retry.
Unknown failures, invalid readiness, integrity errors and compatibility failures
stop startup and produce a report. Business operations are never replayed.

The UI selects one mode for itself and the directly sandboxed Worker. It passes
that mode as the Broker's preference. The Broker performs its own preflight only
after UAC, in the actual administrator context. If that context independently
fails the standard CET check, it may select compatibility before reading a plan.
Worker low-integrity tokens, job limits and protocol remain intact. Installation
blocks inbound and outbound network traffic for both Worker variants and the
legacy alias, and verifies all six firewall rules.

The Broker bootstrap reserves exit `0x53530001` for failure before business
creation. If a business child returns the same number, the wrapper maps it to
`126`. The UI recognizes the reserved code only for the fixed unified wrapper,
clears its not-started pending request and reports the startup failure. It does
not synthesize a protected business receipt. All uncertain business exits retain
the existing pending-result and recovery safeguards.

There is no persistent mode cache: every launch rechecks the actual hosts, so
system patches, policy changes and package updates cannot leave a stale decision.
The first successful compatibility selection displays a local explanatory notice.

## Local diagnostics

No report is uploaded automatically.

- Native startup reports: `%LOCALAPPDATA%\SteamSentinel\Logs\startup-*.txt`.
  If unavailable, `%TEMP%\SteamSentinel-Startup-Reports\startup-*.txt`.
  Reports include OS build/revision, verified package version information when
  available, role/mode, observed process shadow-stack policy, exit/Win32 errors,
  selection reason, and bounded failing-probe output/host trace.
- Managed error reports: `%LOCALAPPDATA%\SteamSentinel\Logs\error-*.log`.
  If unavailable or at the report-count limit, the fallback is
  `%TEMP%\SteamSentinel-Error-Reports`. Each report is bounded to 128 KiB UTF-8,
  with software/runtime identity, host mode, exception chains and stack traces,
  and references to the latest native startup reports. Common credential strings
  and user-profile paths are redacted. Environment dumps, exception `Data`, and
  scanned-file contents are not collected.
- WPF dispatcher errors, fatal domain errors, unobserved task errors and managed
  startup failures use the collector. User-visible errors show the report path;
  the dispatcher dialog can open the report in the default text viewer. Reporting failures are caught
  and cannot recursively trigger another error report.

These reports preserve diagnostic evidence; an unknown error is not automatically
assigned a root cause. OS termination, power loss or failures preventing the
native bootstrap itself from running may still require the external diagnostic
script and Windows event logs.

## Build and validation

`scripts/build-unified-startup.ps1` generates apphosts from the pinned runtime's
pristine template through `HostWriter.CreateAppHost`, compiles the native launcher,
and checks the actual PE extended CET characteristics of all nine EXEs. It also
embeds the original application manifests and product/version resources.

`scripts/build-release.ps1` performs the existing baseline tests, generates and
signs the complete unified payload, writes the manifest, runs
`scripts/Test-UnifiedStartup.ps1`, then verifies the payload was unchanged before
creating ZIP/installer artifacts. Release acceptance requires zero failed or
skipped startup checks. Actual Broker probes require an elevated test session.

The startup tests use real published host probes plus isolated harmless fixtures
for CET fallback, Worker selection, unknown exits, readiness/nonce validation,
timeouts, excessive output, integrity failures, installer-file compatibility,
argument forwarding, and Broker no-replay/exit-code collision behavior. Synthetic
CET failures test the state machine, not the hardware fix. Managed self-tests also
cover report bounds, redaction, write failure, and pending-operation handling.

Before broad rollout, validate the complete installer on actual affected Win10
CET hardware: standard must reproduce the original fatal error, compatibility
must open the UI and complete a safe Worker scan and Broker authorization flow.
Also validate Win10/Win11 upgrade, uninstall, firewall rules, and an administrator
policy that forces CET. Ordinary VMs without exposed CET cannot establish the
hardware-specific repair, and opting out does not override every system policy.
