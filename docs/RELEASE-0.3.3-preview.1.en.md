# SteamSentinel 0.3.3 detects the SteamAlert mod for Deep Space Pawnshop

2026-11-10 · [简体中文](RELEASE-0.3.3-preview.1.md)

Product version **0.3.3** ships with rules `2026.11.10.1` under tag `v0.3.3-preview.1`. Close the application and its administrator window, install the complete package, then rescan. The installer uses the self-signed certificate `CN=fenglinbei`. Windows may warn that the publisher is untrusted. [Download and verification files](https://github.com/fenglinbei/SteamSentinel/releases/tag/v0.3.3-preview.1)

## Scanning and recovery

1. If you installed the mod, run a full scan. Review `3835179592\PWLoader.dll` and `3835252991\PWLoader.dll` under the Workshop or game mod root, and resident executables under `%LOCALAPPDATA%\SteamAlertDemo`. If you received an archive, select it directly for a file scan.
2. Exact SHA-256 matches identify the downloader, resident host and core DLL separately. Finding an installed downloader or host triggers a check for its counterpart at known locations. Review each file and any process or startup entry supported by file evidence before confirming the proposed actions. Archive member paths identify where the files were found inside the package.
3. Static inspection also recognizes mod initialization code that downloads and launches the same executable, a host loading a core from its resources, and Steam debugging behavior associated with persistence. Behavior-only findings require manual review.
4. Legitimate extensions can also change Steam UI scripts. The scanner records the local script endpoint and the file hash. For the known family endpoint it checks the current user's resident host for an exact match before reporting a connection. Address confirmed sources of reinfection first, then repair unexpected client changes with the official Steam installer and rescan.

## Offline verification

The scanner hashed all 30 file members in the original RAR. Both copies of `PWLoader.dll` and the resident host had exact hash matches and one behavior finding each. The embedded `SteamAlertCore.dll` was extracted and verified separately against its core rule. The DailyCheckin and SpeedUp control DLLs raised no findings from these family rules. Verification used static inspection of these samples and controls.

The focused SteamAlert development suite passed 51 checks. The shared false-positive suite passed 164. Both recorded zero failures and zero skips. The release acceptance summary, publication identity and SHA-256 manifest provide the full-suite result, build provenance and final asset hashes. Cleanup and recovery after reboot on an infected machine still require live verification.
