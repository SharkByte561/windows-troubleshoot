---
name: windows-troubleshoot
description: Diagnose and troubleshoot Windows 10/11 and Windows Server problems with Microsoft's TroubleShootingScript toolset (TSS) - map a symptom to the right TSS scenario and exact .\TSS.ps1 command, run a read-only health triage of the local machine (event logs, crashes, BSODs, disks, services, updates, network, domain), and analyze an already-collected TSS / MS_DATA zip into plain-English findings. Use this whenever the user describes a Windows problem (slow PC, crashes, blue screen, account lockouts, logon or GPO problems, DNS/Wi-Fi/VPN/SMB/proxy connectivity, printing, RDP/AVD/Windows 365, Windows Update or activation failures, Start menu/Store/app issues, WMI/WinRM, Hyper-V, clustering), asks "which TSS scenario", "what does TSS collect", "how do I trace X", mentions TSS, MS_DATA, xray or SDP, asks whether TSS is expired or wants it updated, or hands over a support-data zip or .evtx files to read - even if they don't name TSS.
---

# Windows troubleshooting with TSS

TSS is Microsoft Support's own signed PowerShell toolkit. It has 157 scenarios, about 400 trace components, 215 CollectLog sets, 9 SDP reports, 24 auto-stop triggers and 34 xray known-issue checks. It **collects** data very well but explains almost none of it. This skill supplies the missing parts:
- **choosing** what to collect;
- **checking cheaply** before collecting anything;
- **reading** what came back.

The skill folder holds a pre-built catalog of TSS (`references/tss-index.json`), so lookups work even on machines without TSS.

**Running the scripts:** paths are relative to this skill's folder. Use the built-in Windows PowerShell 5.1, which every Windows machine has: `powershell -NoProfile -ExecutionPolicy RemoteSigned -File <script>`. `pwsh` 7 works the same way if it is installed.
- `-ExecutionPolicy RemoteSigned` applies to that one process only. It is needed because Windows clients default to `Restricted`, which blocks every `.ps1` file. Never use `Bypass` (see `references/safety.md`).
- If a script is still blocked because the skill was downloaded as a zip ("not digitally signed"), run `Unblock-File` on this skill's own `scripts\*.ps1`, never on TSS.
- If Group Policy sets the execution policy, the switch has no effect. That is the admins' decision, so tell the user.

**Where TSS lives:** the scripts find a local TSS copy with `scripts/Resolve-TssRoot.ps1`. It checks `$env:TSS_ROOT` first, then the folder saved by `Update-Tss.ps1` or `Resolve-TssRoot.ps1 -Save <folder>`, then `C:\TSS`.
- Triage, package analysis and scenario lookup don't need a local copy.
- To get one, run `scripts/Update-Tss.ps1` (tier 2). It installs a verified copy to `C:\TSS` (or `-TssRoot <folder>`) and saves its location.

## Workflow

Not every request needs every step. A user who hands over a zip jumps straight to step 5. A user who only asks "which scenario for X" needs step 3 alone.

### 1. Pin down the symptom

Get these before anything else:
- what fails, and the exact error text or code
- since when, and what changed around then (update, driver, policy, network)
- whether it affects one user/machine or many
- whether it can be reproduced on demand, or happens intermittently
- which side to look at for client/server problems

Ask only for what you can't infer. These answers decide the scenario and where it runs.

### 2. Quick read-only triage (on the affected machine)

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts/Invoke-QuickTriage.ps1 [-Hours 72] [-NoNetworkTests]
```

- Takes about 20 s and needs no admin. It writes `triage.md` and `triage.json` to `%TEMP%\win-triage\<timestamp>\`.
- It changes nothing. The network tests send one gateway ping, one DNS lookup and one HTTP GET to msftconnecttest.com; skip them with `-NoNetworkTests`.
- Elevated, it also reads the Security log (lockouts, failed logons) and tests the domain secure channel.

Set `-Hours` to cover "since when" plus a margin. For something that started "last week", use `-Hours 240`.

Read `triage.md`. Its **Flags** table is a set of leads, not a verdict. Relate the flags to the user's symptom and ignore the rest. Many problems end here: a full disk, a pending reboot, a stopped core service, an APIPA address, a broken secure channel, repeated bugchecks. In those cases, explain the fix and offer to stop before any heavy tracing.

### 3. Pick the TSS scenario

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts/Find-TssScenario.ps1 "users keep getting locked out"
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts/Find-TssScenario.ps1 -Name ADS_AccountLockout      # full entry
```

- It returns ranked scenarios, CollectLogs, SDP reports and components, each with the exact command, a "use when" line, the add-on tools and the side-effect sentences.
- Read the full description of your pick (`-Name`). It says **where to run** the scenario and **what it changes**.
- Prefer the lightest option that answers the question: `-CollectLog` (static logs) beats `-Scenario` (live trace), and the "Ex" variants add a network capture and PSR, which makes them heavier.
- Not every problem is a TSS problem. A "weak matches only" warning means no scenario fits.
  - Crashes and blue screens are solved from the dump: WinDbg `!analyze -v` on the minidump that triage lists.
  - Disk-full, hardware (WHEA) and pending-reboot problems are solved from the triage itself.
  - The `-SDP Perf` report from the Learn pages is deprecated in this TSS version.
- For problems that can't be reproduced on demand, add an auto-stop trigger from `references/waitevent-recipes.md`, for example `-WaitEvent Evt:4740:Security`.
- `references/scenario-index.md` is the browsable list, grouped by area.

### 4. Hand over (or run) the collection

TSS traces are **tier 3** in `references/safety.md`: they change audit policy, debug registry keys and caches, and can produce gigabytes of sensitive data.

1. Present the command, where to run it, the side effects, the expected size, and the prerequisites from `references/running-tss.md`: elevated console, signature check, process-scope execution policy, and a fresh TSS (it refuses to run after 90 days).
   - `Find-TssScenario.ps1` prints the expiry on every lookup. If the copy is expired or close to it, offer `scripts/Update-Tss.ps1`, which is tier 2: it downloads, verifies the hash and signatures, and installs next to the old copy. `-CheckOnly` only compares versions.
   - If updating isn't possible right now (offline machine, or a collection that must match an earlier one), adding `-noExpire` to the TSS command is Microsoft's built-in override. Say what it costs: definitions frozen at that build, and support may ask for a rerun on the current version.
2. Run it yourself only after an explicit yes, and only on a machine the user administers.
3. Usually the user runs it, because a reproduction needs them in front of the machine anyway.

Never use `-Crash`, notmyfault, or machine-wide execution-policy changes unless the user explicitly asks for them.

### 5. Analyze the collected package

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts/Read-TssPackage.ps1 <C:\MS_DATA\TSS_...zip | folder> [-OutDir <dir>] [-ExtractDir <short dir>]
```

A zip is unpacked to `%TEMP%\tssx\<id>` unless you pass `-ExtractDir`. Pass it when the user wants everything kept in one case folder, and keep that path short.
- Windows PowerShell 5.1 can't handle paths over 260 characters, and TSS file names are long. The script refuses an `-ExtractDir` over 80 characters or an `-OutDir` over 200. Use something like `C:\cases\<case>`, then copy the summaries wherever they need to go.

The script reads the package without changing it. It produces `package-summary.md` and `package-summary.json` with:
- metadata (computer, scenario, time, OS build)
- xray issues found
- per-event-log key events and top errors
- the most frequent error codes in the text logs
- the last failure lines in setup/servicing logs
- TSS's own collection warnings, and **near-empty trace files**. A 6-byte `.etl` means the capture never ran, so say so before reasoning from it.
- an inventory, including the **sensitive files** list. This also covers event logs whose text contains e-mail addresses or user profile names, which Outlook and Office events often do.

Then go further than the summary:
- Open the specific files it points at. `references/package-anatomy.md` says what to read first for each scenario family and which tool decodes `.etl`, `.blg`, `.pml` and `.dmp`.
- Treat xray findings and event patterns as hypotheses, and test each one against the machine's real configuration. If the affected machine is reachable (often it is the one you are on), check the setting read-only. For example: NRPT rule conflict → `Get-DnsClientNrptPolicy` and whether the machine is domain-joined at all. VPN/overlay clients such as Tailscale or Zscaler create local NRPT rules legitimately, and a check that doesn't fit the machine is a false positive worth saying so.
- Ask when the problem reproduced, and weight the events in that time window.
- Separate signal from background noise; the anatomy page lists the usual noise. Then name the noise in the report (step 6), so the reader doesn't chase it.
- If TSS logged collection warnings, say which data is missing.

### 6. Report

Use this shape. Keep it short and specific to the symptom:

```
## Diagnosis: <one line>
**Confidence:** high / medium / low, and why.
## Evidence
- <file or check> → <what it shows, with timestamp/count/code>
## Not related (background noise)
- <provider/ID or code, count> → <why it's unrelated to this symptom, e.g. DCOM 10010, BitLocker 24641, Store 0x80073D02>
## Fix
1. <step> (tier 1/2/3 per safety.md, needs admin?)
## If that doesn't resolve it
- next collection: <exact .\TSS.ps1 command>, run on <machine>, reproduce, send <zip>
## Before sharing the data
- <sensitive files from the package summary, and what to drop>
```

Describe personal data you find (e-mail addresses, SIDs, serial numbers, IPs, user names), giving counts and which file it's in, but don't copy it into your answer. The answer often ends up in the same ticket you're trying to keep clean.

Say plainly what you didn't check, or what the data can't show (for example, a component ETL that only Microsoft can decode).

## Gotchas

- **Use one scenario at a time.** Components and CollectLogs can be combined, but scenarios can't.
- **Check where the scenario runs.** Lockout and KDC scenarios belong on the domain controller. SMB, RDS and DNS have separate client and server scenarios. Running on the wrong side gives a clean trace and a wrong conclusion.
- **xray mostly needs the live machine.** None of the 34 checks in this TSS version runs offline, so `xray.ps1 -Offline` against a package finds nothing. Read the `xray_*` files that were produced during collection instead (`references/xray-checks.md` lists the checks with their KB articles).
- **Refresh the index when TSS changes.** `Update-Tss.ps1` rebuilds it for you. If the user gets a newer TSS some other way, run `scripts/Build-TssIndex.ps1 -TssRoot <folder>` so names and options match. The lookup warns when the index and the copy on disk differ.
- **Background noise is normal.** Healthy Windows logs DCOM 10010/10016, Perflib, BitLocker 24641 and Store 0x80073D02 errors constantly. Don't build a diagnosis on them unless they line up with the symptom in time.

## Files

- `scripts/Invoke-QuickTriage.ps1`: read-only live health snapshot.
- `scripts/Find-TssScenario.ps1`: symptom → TSS command; `-Name` gives the full entry; `-AsJson` for parsing.
- `scripts/Read-TssPackage.ps1`: offline analysis of an MS_DATA zip or folder.
- `scripts/Update-Tss.ps1`: `-CheckOnly` compares the local copy with the published version. Without it, the script downloads, verifies and installs a newer TSS to `TSS_<version>`, then rebuilds the index.
- `scripts/Resolve-TssRoot.ps1`: prints the local TSS folder, if any; `-Save <folder>` records a copy kept somewhere else.
- `scripts/Build-TssIndex.ps1`: regenerates the `references/` catalog from a TSS folder (reads only its JSON and xray source).
- `references/running-tss.md`: prerequisites, command patterns, output layout, the 90-day expiry.
- `references/safety.md`: tiers, hard stops, known side effects, data sharing.
- `references/package-anatomy.md`: what to read per scenario family, decoding tools, noise, error codes.
- `references/scenario-index.md`, `waitevent-recipes.md`, `xray-checks.md`, `tss-index.json`: generated catalog.
