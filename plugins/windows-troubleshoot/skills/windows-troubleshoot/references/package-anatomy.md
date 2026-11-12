# Reading a TSS package by hand

`Read-TssPackage.ps1` covers event logs, xray and text logs. Use this page for the parts it only lists, and for the questions to ask of each.

## Where to look first, by scenario family

| Scenario prefix | Look at first | Then |
|---|---|---|
| `NET_DNScli`, `NET_WinSock`, `NET_Proxy`, `NET_NCSI` | `*_evt_System.evtx` (DNS-Client 1014, Tcpip 4199), DNS client text output (`ipconfig /displaydns`, NRPT), xray | NetTrace `.etl` / `.pcapng` |
| `NET_SMBcli/srv`, `NET_DFScli` | SMBClient/SMBServer operational evtx (30800-30833 connectivity, 31010 write failures), `net use` output | packet capture filtered on tcp/445 |
| `NET_WLAN`, `NET_802Dot1x` | WLAN-AutoConfig operational log (8001 connect, 8003 disconnect + reason code), `netsh wlan show wlanreport` HTML | netsh trace |
| `ADS_Auth*`, `ADS_AccountLockout*` | Security evtx (4625 status/substatus, 4740 caller computer, 4771 failure code), Netlogon.log (`0xC000006A` bad password, `0xC0000234` locked) | Kerberos/NTLM ETL (needs Microsoft decoding) |
| `ADS_GPOEx` | `gpresult` HTML, GroupPolicy operational evtx (4016/5016/7016 timings, 1058/1129 errors), gpsvc.log | — |
| `UEX_Logon`, `PRF_Boot`, `ADS_SBSL` | User Profile Service evtx (1511 temp profile, 1530/1534), Winlogon/GP timings, WPR boot trace | WPA boot analysis |
| `PRF_General`, `PRF_HighCPU` | PerfMon `.blg` (Processor, Memory\Available MBytes, Pool Nonpaged), WPR `.etl` | WPA CPU Usage (Sampled) |
| `DND_Servicing`, `-CollectLog DND_SetupReport` | CBS.log, `setupact.log`/`setuperr.log` (Panther), WindowsUpdate.log, DISM.log: search the last `Error`/`0x8` lines | — |
| `UEX_Print*` | PrintService operational/admin evtx (808 driver load, 372 failed job), spooler driver list | ProcMon |
| `UEX_RDS*`, `UEX_AVD*`, `UEX_W365*` | MSRD-Collect HTML report (`MSRD-Diag.html`), TerminalServices-* operational evtx, RDP client logs | — |
| `-SDP <x>` | The SDP HTML/XML result report at the top of the SDP folder | raw command output |

## Files the script does not decode

| File | Tool | What to look for |
|---|---|---|
| `*.etl` from netsh/PktMon (NetTrace, PktMon) | `pktmon etl2pcap <file>.etl -o out.pcapng` (PktMon, built in), then Wireshark. Older netsh ETLs: Microsoft Network Monitor / etl2pcapng (GitHub microsoft/etl2pcapng) | TCP resets/retransmits, DNS responses (rcode), TLS alerts, SMB error status |
| other `*.etl` (component ETW/WPP) | Usually needs Microsoft's private TMF symbols, so it's only meaningful to Microsoft Support. `tracerpt <file>.etl -o out.xml -of XML` gives some manifest-based providers | Don't spend time on it; pass it to the support engineer |
| WPR `*.etl` | Windows Performance Analyzer (WPA, from the Windows ADK) | CPU Usage (Sampled) by process/stack, Disk IO, Boot phases |
| `*.blg` | `relog file.blg -f csv -o out.csv`, or open in PerfMon | Sustained processor > 80 %, Available MBytes trending down, pool growth |
| `*.pml` | Process Monitor (File > Open) | `ACCESS DENIED`, `NAME NOT FOUND` near the failure timestamp |
| `*.dmp` | WinDbg: `!analyze -v` | Faulting module / bugcheck code |
| `*.evtx` with other names | `Get-WinEvent -Path <f> -MaxEvents 200 \| ? Level -le 2` | — |

## Interpreting results

- **Line up timestamps.** Ask the user roughly when the problem reproduced during the trace, and filter every source to that window. Errors from outside the repro window are usually noise.
- **Expect background noise on healthy machines.** DCOM 10010/10016, Perflib 1008/1023, BitLocker 24641 at boot, DistributedCOM timeouts and Store app update failures (0x80073D02 = app in use) show up everywhere. Mention them only if they line up with the symptom.
- **Treat TSS warnings as gaps.** Lines in `*_Log-Warn-Err-Info.txt` mean part of the collection failed, for example an event log that couldn't be exported because of access denied. Say what is missing before you draw conclusions from its absence.
- **Translate error codes.**
  - `0x8007xxxx` is a Win32 error in the low 16 bits; `0x80070005` is access denied.
  - Use `certutil -error 0x<code>` (read-only) for a readable name.
  - `0xC000xxxx` is an NTSTATUS code. Common ones: `0xC000006A` wrong password, `0xC0000234` account locked, `0xC0000064` no such user, `0xC000018D` trust failure.
