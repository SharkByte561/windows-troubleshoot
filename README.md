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
