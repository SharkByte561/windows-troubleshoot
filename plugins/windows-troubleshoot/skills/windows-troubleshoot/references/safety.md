# Safety tiers and what TSS changes on a machine

The skill works in three tiers. The tier decides whether you may just run a step or must ask first.

| Tier | What | Rule |
|---|---|---|
| 1. Read-only | `Invoke-QuickTriage.ps1`, `Find-TssScenario.ps1`, `Read-TssPackage.ps1`, `Update-Tss.ps1 -CheckOnly`, `Get-WinEvent`, `Get-Cim*`, `ipconfig /all`, `gpresult /r`, `w32tm /query`, `dsregcmd /status`, reading files | Run it. Say what you ran. |
| 2. Light, targeted | Single-purpose collectors from `TSS\scripts` (e.g. `tss_GetLockoutEvents.ps1`, `SpeculationControl`), `xray.ps1 -Component <x>` on the live machine, `-CollectLog <x>`, `Update-Tss.ps1` without `-CheckOnly` (downloads and writes; no admin) | Needs admin. Name the command and what it reads, then run it once the user agrees. |
| 3. Tracing / system-changing | `-Scenario`, `-Start -<Component>`, `-StartAutoLogger`, `-SDP`, `-Netsh`, `-Procmon`, `-WPR`, `-ProcDump`, `-PSR`, `-Video` | **Always confirm first**, listing the side effects from the scenario description and the expected data size. Give the user the command to run, or run it only after an explicit yes. |

Hard stops. Don't run these, and don't suggest them unless the user explicitly asks and understands the risk:
- `-Crash`, `notmyfaultc.exe`, `kdbgctrl`: these deliberately crash the machine, and unsaved work is lost.
- Machine-wide execution-policy changes (the docs' Method 2/3, `HKLM:\...\Policies\...\PowerShell`), `Unblock-File` on the whole folder, `-ExecutionPolicy Bypass`.
- `BIN\SQLCheck.exe`: its signature does not validate (expired internal certificate).
- Running TSS on a machine the user does not administer, or for anyone other than the user's own support case.

## Known side effects (from TSS FAQ and scenario descriptions)

- TSS sets debug-logging registry keys and normally reverts them at `-Stop`. If a run was aborted, `.\TSS.ps1 -Stop -noBasiclog -noXray` cleans up.
- Network scenarios flush the ARP, DNS and NetBIOS caches and put NICs in promiscuous mode for the capture.
- **Audit policy is not restored.**
  - `ADS_AccountLockout*` sets the Security log to 100 MB with overwrite, enables success/failure auditing for 10 subcategories, and turns on Netlogon debug logging.
  - At stop it sets those subcategories to **No Auditing** and does not restore the earlier values.
  - The Security log size isn't restored either, and Netlogon `DBFlag` is set to `0x0` at stop, which wipes any earlier value.
  - "Set to 100 MB" can **shrink** the log. DCs often keep a larger Security log, so the trace cuts retention and older events are overwritten sooner. Export the events you need first (`wevtutil epl Security <file>.evtx`).
  - At stop, TSS also runs `wevtutil set-log Security /enabled:false`. Windows may refuse this for the Security log, but check afterwards: `wevtutil gl Security` must show `enabled: true`. If it doesn't, run `wevtutil sl Security /e:true` at once, because the DC stops recording security events.
- `-CollectLog ADS_LockOut` runs `tss_GetLockoutEvents.ps1`. It prompts interactively for the user (sAMAccountName) and the domain, because TSS doesn't pass them, so it can't run unattended. It needs Domain Admin rights and the ActiveDirectory PowerShell module (RSAT). It only reads events, so it is tier 2.
  - Before starting, capture:
    - `auditpol /backup /file:C:\temp\audit-before.csv`
    - `wevtutil gl Security`
    - the Netlogon `DBFlag` value
  - Restore afterwards with `auditpol /restore /file:...`, `wevtutil sl Security /ms:<old>`, and `gpupdate /force` where GPO sets auditing.
- `-StartAutoLogger` persists across reboot until `-Stop`.
- TSS can run helper code through transient scheduled tasks named `TSS-Framework_*` using `-ExecutionPolicy Bypass` on a temp script. This is expected. Mention it if the user's EDR alerts on it.
- xray runs on every collection unless `-noXray`, and TSS checks online for updates.

Before any tier-3 run, read the scenario's full description with `Find-TssScenario.ps1 -Name <Scenario>`. The `SideEffects` field pulls out the sentences that mention changes. Read the whole description anyway, because the extraction is heuristic.

## Sharing collected data

TSS output can contain:
- packet captures
- memory and process dumps
- the Security log (user names, source IPs)
- ProcMon (every file and registry path)
- screen recordings
- environment variables
- Wi-Fi and VPN profiles

`Read-TssPackage.ps1` lists these under "Sensitive before sharing". Before the data goes to a vendor or a ticket:
1. Share only with the support engineer on the case, through the case's secure file transfer. Don't use email or chat attachments.
2. Delete what the case does not need, such as dumps or a Security log for a printing case. The cleanest fix is a narrower re-collection (`-Mini`, no `-Netsh`).
3. Delete local copies under `C:\MS_DATA` when the case closes. They are not cleaned up automatically.
