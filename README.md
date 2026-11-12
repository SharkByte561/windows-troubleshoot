# windows-troubleshoot

A Claude Code skill for diagnosing Windows 10/11 and Windows Server problems with
Microsoft Support's **TroubleShootingScript toolset (TSS)**.

TSS collects data very well but explains almost none of it. This skill fills the gaps:

- **Choose what to collect.** Describe the symptom (slow PC, BSOD, account lockouts,
  GPO, DNS/Wi-Fi/VPN/SMB, printing, RDP/AVD, Windows Update, WMI, Hyper-V, clustering…)
  and get the right TSS scenario and the exact `.\TSS.ps1` command.
- **Check cheaply first.** A read-only triage of the local machine: event logs, crashes,
  disks, services, updates, network and domain health.
- **Read what came back.** Point it at a TSS / `MS_DATA` zip or `.evtx` files and get
  plain-English findings, including what to redact before uploading.

A prebuilt catalog of TSS (`references/tss-index.json`) ships with the skill, so scenario
lookups work even on machines without TSS installed.

## Install

As a Claude Code plugin:

```
/plugin marketplace add SharkByte561/windows-troubleshoot
/plugin install windows-troubleshoot@windows-troubleshoot
```

Or copy the skill folder by hand:

```powershell
git clone https://github.com/SharkByte561/windows-troubleshoot
Copy-Item -Recurse windows-troubleshoot\plugins\windows-troubleshoot\skills\windows-troubleshoot `
  $HOME\.claude\skills\
```

If you downloaded a zip, run `Unblock-File` on the skill's `scripts\*.ps1`.

## Requirements

- Windows PowerShell 5.1 (built in) or PowerShell 7.
- [Microsoft TSS](https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss)
  for actual collection. The skill finds it via `$env:TSS_ROOT`, a saved folder, or `C:\TSS`,
  and `scripts/Update-Tss.ps1` can download or refresh it.

Scripts run with `-ExecutionPolicy RemoteSigned` for their own process only, never `Bypass`.

## TSS expires after 90 days

Every TSS build has a time limit. `TSS.ps1` compares today with its own build date
(`$global:TssVerDate`) and refuses to start once that gap is **more than 90 days**. A copy
still runs on day 90 and stops on day 91 with:

```
TSS script is outdated more than 90 days. Please -Update or download latest version: 'https://aka.ms/getTSS'
```

| Build | Runs through | Stops on |
| --- | --- | --- |
| 2026.11.02.0 (the build this skill's catalog was made from) | 2027-01-31 | 2027-02-01 |

Some comments inside TSS say 30 days. The code checks 90.

Expiry is separate from TSS's online check. Each time a collection starts (`-Scenario`,
`-Start`, `-StartAutoLogger`, `-CollectLog`), TSS also looks on `download.microsoft.com` for a
newer build and offers to update (Y/N, 30 s). If it can't reach the site, it asks whether to
continue and exits after 20 s with no answer, so an unattended run on an offline server just stops.

The skill tracks this for you. `scripts/Find-TssScenario.ps1` prints the expiry date on every
lookup and warns when 14 days or fewer are left.

## Keeping it up to date

There are three things to keep current: TSS itself, the skill's TSS catalog, and the skill.

**TSS.** Pick one of these:

```powershell
# Check only: compares your copy with the published version (downloads a few bytes)
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts\Update-Tss.ps1 -CheckOnly

# Update: download, verify, install next to the old copy, rebuild the catalog (about 25 MB)
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts\Update-Tss.ps1
```

`Update-Tss.ps1` checks the zip's SHA256 against `aka.ms/getTSSHash` and requires a valid
*Microsoft Corporation* signature on every `.ps1`, `.psm1` and `.psd1`. It installs to
`TSS_<version>` beside the old folder (or `C:\TSS` the first time) and never changes the old copy.

On a machine that only runs TSS, Microsoft's own updater does the same job in place:

```powershell
.\TSS.ps1 -Update      # verifies the hash, keeps a TSS.ps1_v<old> backup
```

Or download a fresh `TSS.zip` from https://aka.ms/getTSS by hand, then check it before
running anything:

```powershell
Get-AuthenticodeSignature C:\TSS\TSS.ps1   # expect Status = Valid, signer CN=Microsoft Corporation
```

**The catalog.** `references/tss-index.json` lists every scenario, component and switch for one
TSS build. `Update-Tss.ps1` rebuilds it automatically. If you got TSS some other way, rebuild it
yourself so names and options match your copy:

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File scripts\Build-TssIndex.ps1 -TssRoot C:\TSS
```

**The skill.** If you installed it as a plugin:

```
/plugin marketplace update windows-troubleshoot
```

If you copied the folder by hand, `git pull` and copy it again.

### When you can't update

For an offline or air-gapped machine, or a collection that has to match an earlier one, TSS has
two built-in switches:

| Switch | What it does |
| --- | --- |
| `-noUpdate` | Skips the online version check and the auto-update prompt. |
| `-noExpire` | Runs a copy older than 90 days. TSS logs the "outdated" error, then continues with a warning. |

```powershell
.\TSS.ps1 -Scenario NET_DNSCli -noUpdate -noExpire
```

The cost of `-noExpire`: scenario definitions and xray known-issue checks stay frozen at that
build, and Microsoft Support may ask you to collect again with the current version. Don't edit
the date inside `TSS.ps1` instead. That breaks its Authenticode signature.

## Official Microsoft links

| What | Link |
| --- | --- |
| TSS overview, prerequisites, switches, FAQ and EULA | https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss |
| Networking scenarios | https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/collect-data-analyze-troubleshoot-windows-networking-scenarios |
| Performance scenarios | https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/collect-data-analyze-troubleshoot-performance-scenarios |
| Active Directory scenarios | https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/collect-data-analyze-troubleshoot-active-directory-scenarios |
| xray known-issue checks | https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/use-the-xray-feature-of-tss-to-identify-known-issues |
| Download TSS (always the latest) | https://aka.ms/getTSS |
| Download TSS lite (no external tools) | https://aka.ms/getTSSlite |
| Published hash of the current zip | https://aka.ms/getTSSHash |

## Layout

```
.claude-plugin/marketplace.json
plugins/windows-troubleshoot/
  .claude-plugin/plugin.json
  skills/windows-troubleshoot/
    SKILL.md
    references/   TSS catalog, scenario index, safety and package notes
    scripts/      triage, scenario finder, package reader, TSS updater
    evals/        test prompts
```

## License

MIT. TSS itself is Microsoft's and is not included.
