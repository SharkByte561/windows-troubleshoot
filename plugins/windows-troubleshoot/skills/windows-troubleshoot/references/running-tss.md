# Running TSS: prerequisites, patterns, gotchas

Read this before you hand the user, or run, any `.\TSS.ps1` command. Source: Microsoft Learn TSS intro page (ms.date 2026-02-12) and `help/TSS_FAQ.json`, checked against TSS 2026.11.02.0.

## Where TSS lives

- Local copy: whatever `scripts/Resolve-TssRoot.ps1` finds (`$env:TSS_ROOT`, then the saved folder, then `C:\TSS`). If it prints nothing, there is no local copy.
- For a real run, copy a **fresh** `TSS.zip` from https://aka.ms/getTSS to `C:\TSS` on the target machine. A smaller "TSS lite" without the external exes is at https://aka.ms/getTSSlite.
## Expiry and updates

- **TSS stops working 90 days after its build date.** The date comes from `$global:TssVerDate` in TSS.ps1, and the check is in TSS.ps1 around the "outdated more than 90 days" message. Some of TSS's own comments say 30 days; the code uses 90.
  - The boundary: TSS refuses when `(today - build date).Days -gt 90`, so a copy **still runs on day 90** and stops on day 91. Example: a 2026-08-11 build runs through 2026-11-09.
  - `Find-TssScenario.ps1` prints the expiry on every lookup and warns when 14 days or fewer are left, or when the copy has expired.
- **Check for a new release** (read-only, a few bytes): `scripts/Update-Tss.ps1 -CheckOnly`. It compares the local version with `aka.ms/getTSS/TSS.ver`, the file TSS's own online check reads.
- **Update** (tier 2: internet, about 25 MB written; ask first): `scripts/Update-Tss.ps1`. It does nothing when the copy is already current.
  1. Downloads `aka.ms/getTSS/TSS.zip` and checks its SHA256 against `aka.ms/getTSSHash`.
  2. Requires every .ps1, .psm1 and .psd1 to carry a valid Microsoft Corporation signature.
  3. Installs the release to `TSS_<version>` next to the old folder, or to `C:\TSS` (or `-TssRoot`) when there's no local copy yet. The old copy is never changed.
  4. Saves the new folder's location and rebuilds the catalog.

  On a machine that only *runs* TSS, `.\TSS.ps1 -Update` does the same job in place: it verifies the hash, deletes files that aren't in the new zip, and keeps a `TSS.ps1_v<old>` backup.
- **Overriding the expiry:** TSS has a built-in switch for this. Add `-noExpire` to the TSS command, for example `.\TSS.ps1 -Scenario NET_DNScli -noExpire`. TSS still logs the "outdated" error, then continues with a warning.
  - Use it only for a one-off run where updating isn't possible right now: an offline or air-gapped machine, or a case that must match an earlier collection.
  - Tell the user the trade-off: scenario definitions and xray checks are frozen at that build, and Microsoft Support may ask for a recollection with the current version.
  - Don't edit `$global:TssVerDate` or patch the check. That invalidates TSS.ps1's Authenticode signature, and with it the signature check under Prerequisites.
- **Online check, separate from expiry:** when it starts a collection, TSS also checks `download.microsoft.com` for a newer version. This happens for `-Start`/`-Scenario`, `-StartAutoLogger` and `-CollectLog`.
  - If the site can't be reached (offline server), TSS asks Y/N to continue. After 20 s it takes **N** and exits, so an unattended run just stops.
  - If a newer version exists, it offers to auto-update (Y/N, 30 s).
  - `-noUpdate` skips both. `-noExpire` doesn't. For an offline or air-gapped server, add `-noUpdate`, and add `-noExpire` too if the copy is past 90 days.

## Prerequisites

1. Elevated **Windows PowerShell or pwsh console**, not ISE.
2. Signature check: `Get-AuthenticodeSignature C:\TSS\TSS.ps1`. Expect `Valid`, signer `CN=Microsoft Corporation`. Known exception: `BIN\SQLCheck.exe` is signed with an expired internal MSIT certificate. Don't treat it as trusted and don't run it on its own.
3. Execution policy for **this window only**: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force`.
   Don't use the docs' "Method 2/3" fallbacks: they write machine-wide policy keys under `HKLM:\Software\Policies`. If GPO blocks scripts, that is a conversation with whoever owns the policy.
4. EULA: shown once interactively. `-AcceptEula` skips it, but only use that after the user has read and accepted the EULA.
5. Free disk space: traces with `-netsh`, `-Procmon` or `-WPR` can reach several GB. Put them on another drive with `-LogFolderPath D:\MS_DATA`.

## Command patterns

```powershell
.\TSS.ps1 -Scenario <Name>                       # start, reproduce, press Y to stop
.\TSS.ps1 -StartNoWait -Scenario <Name>          # start and return; later: .\TSS.ps1 -Stop
.\TSS.ps1 -StartAutoLogger -Scenario <Name>      # boot-time trace: reboot, reproduce, .\TSS.ps1 -Stop
.\TSS.ps1 -CollectLog <Name>[,<Name>]            # one-shot log/config collection, no tracing
.\TSS.ps1 -SDP <Report> [-SkipSDPList skipBPA,skipHang]
.\TSS.ps1 -Start -<Component>[ -<Component>]     # individual component traces, combinable
.\TSS.ps1 -Scenario <Name> -WaitEvent <Type>:<params>   # auto-stop on a condition, see waitevent-recipes.md
.\TSS.ps1 -Status                                 # what is running
.\TSS.ps1 -Stop -noBasiclog -noXray               # clean up after a crashed/aborted run
```

Useful options:
- `-AddDescription "<ticket/text>"`
- `-EvtDaysBack <N>` (default 30)
- `-Mini` (smaller data set)
- `-noXray`
- `-Discard` (throw the data away at `-Stop`)
- `-noBasicLog`
- `-LogFolderPath`
- `-RemoteRun` (PsExec / PS remoting)

Add-on tools (combine them with a scenario):
- `-Netsh` / `-PktMon`: packet capture
- `-Procmon`
- `-PerfMon General -PerfIntervalSec 10`
- `-WPR General` or `-WPR CPU`
- `-Xperf Pool -XperfTag <tags>`
- `-ProcDump <pid|name.exe|service> -ProcDumpOption Both`
- `-PSR`
- `-Video`
- `-Radar <proc>`

Only **one** `-Scenario` is allowed per run. Several components and several CollectLogs can be combined.

## Discovery commands (these run TSS but only print help)

`-ListSupportedScenarioTrace`, `-ListSupportedTrace`, `-ListSupportedCollectLog`, `-ListSupportedSDP`, `-ListSupportedNetshScenario`, `-ListETWProviders <name>`, `-Help <keyword>`, `-Find <keyword>`, `-Search <keyword>`.
The skill's `Find-TssScenario.ps1` answers the same questions from the JSON files without starting TSS.

## Output

- Default folder: `C:\MS_DATA\TSS_<COMPUTER>_<yyMMdd-HHmmss>_<scenario>\`, zipped at `-Stop` as `C:\MS_DATA\TSS_...zip`.
- File names inside start with `<COMPUTER>_<yyMMdd-HHmmss>_`.
- Event logs are named `*_evt_<LogName>.evtx`.
- TSS's own problems are logged in `*_Log-Warn-Err-Info.txt` and `*Command-Error.txt`.
- xray results are in `xray_ISSUES-FOUND_*.txt` and `xray_report_*.xml`.
- Basic system info (OSVersion-Build, hotfixes, bcdedit, powercfg, WER) is in `BasicLog`.

Hand the zip to `scripts/Read-TssPackage.ps1`.

## Where to run it

Many scenarios only make sense on one side of the problem:
- Account lockout and KDC issues: on the domain controller.
- SMB: `NET_SMBcli` on the client, `NET_SMBsrv` on the server.
- RDS: `UEX_RDScli` on the client, `UEX_RDSsrv` on the host.

The scenario's description in `tss-index.json` says where to run it. Read it with `Find-TssScenario.ps1 -Name <Name>`. For client/server problems, run on both sides at the same time and reproduce once.
