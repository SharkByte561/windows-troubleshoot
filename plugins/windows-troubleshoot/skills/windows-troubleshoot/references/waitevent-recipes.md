# Stop triggers for intermittent problems (-WaitEvent), TSS 2026.11.02.0

Pattern: `.\TSS.ps1 -Scenario <Name> -WaitEvent <Type>:<params>` starts the trace and stops it automatically when the condition hits. Add `-StartNoWait` to return the console immediately. Source: `help/TSS_Monitoring.json`.

## Evt (Event Log Monitoring)

Monitors Windows Event Logs and automatically stops data collection when specific event(s) are recorded. This is the most commonly used monitoring method for capturing issues that generate event log entries. The monitoring checks for new events at regular intervals (default 5 seconds) and can filter by event data content. Use this when you know which event ID(s) indicate the problem occurrence. Supports monitoring multiple event IDs simultaneously and filtering by specific text or error codes within the event data. The partial match option allows flexible string searching within event XML data fields. Field-specific filtering allows targeting exact event data field names (e.g., Reason, Session) to avoid false matches when the same value appears in multiple fields.

Format: `Evt:<EventID>:'<Eventlog Name>'[:<CheckIntInSec>:<StopWaitTimeInSec>:<StopEventData>:<EvtDataPartial>:<OR|AND>:<StopEventDataName>]`

```powershell
.\TSS.ps1 -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:0:user1/user2:True:OR  # Monitor Security EventID 4625 for partial string 'user1' OR 'user2' in any event data field
.\TSS.ps1 -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:2:user1/0xc000006a:False:AND  # Monitor Security EventID 4625 for exact match of 'user1' AND error code '0xc000006a' in the same event, wait 2 seconds after the event
.\TSS.ps1 -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:2:user1/0xc000006a:False:AND:TargetUserName/Status  # Same as above, but each value is bound to its own field: TargetUserName='user1' AND Status='0xc000006a'. Preferred form - it cannot match the right value in the wrong field
.\TSS.ps1 -Scenario NET_DNSCli -WaitEvent Evt:7034:'System':5:2:'DNS Client':False  # Monitor System EventID 7034 for exact string 'DNS Client' (space requires quotes)
```

## PortLoc (Local Port Monitoring)

Monitors whether a TCP port on the local machine is still in the Listening state and stops data collection when the port is no longer listening. Use this for scenarios where local services stop listening on their designated ports (e.g., SMB port 445, HTTP port 80, SQL port 1433). This is particularly useful for troubleshooting service failures, port exhaustion, or when applications lose the ability to accept network connections. At each check interval the monitoring queries the local listeners with Get-NetTCPConnection -State Listen (it does not open a new connection); when no listener remains on the port the event is signaled. Multiple local ports can be supplied separated by '/'.

Format: `PortLoc:<Port number>`

```powershell
.\TSS.ps1 -NET_SMBsrv -WaitEvent PortLoc:445 -StopWaitTimeInSec 10  # Wait for local port 445 (SMB) to close, then wait 10 more seconds
```

## PortDest (Remote Port Monitoring)

Monitors the availability of a TCP port on one or more remote servers and stops data collection when the port(s) become unreachable. Essential for troubleshooting network connectivity issues, remote service failures, or intermittent connection problems to specific servers. Supports monitoring multiple remote hosts simultaneously (comma-separated list). Use this when investigating client-side connectivity problems, SMB access issues to file servers, database connection failures, or remote desktop disconnections. The monitoring performs TCP connection attempts to each specified host at regular intervals. Useful for capturing network traces leading up to the moment a remote service becomes inaccessible.

Format: `PortDest:'<RemoteHost1,Host2>':<Port number>`

```powershell
.\TSS.ps1 -NET_SMBcli -WaitEvent PortDest:'server1.contoso.com':445  # Wait for port 445 on server1.contoso.com to become unreachable
.\TSS.ps1 -Netsh -WaitEvent PortDest:'10.0.0.1,10.0.0.2':3389  # Wait for port 3389 (RDP) on multiple servers to close
```

## NoNetConn (Network Connectivity Monitoring)

Monitors network connectivity via ICMP ping to the default gateway (or specified destination) and stops data collection after a specified number of consecutive ping failures. This is ideal for capturing intermittent network connectivity losses, dropped connections, or when investigating network infrastructure issues. By default, monitors the default gateway (most common for local network issues). Can specify a remote host like a DNS server (8.8.8.8), domain controller, or internet destination to monitor specific network paths. The consecutive failure count prevents false triggers from occasional packet loss. Use this for troubleshooting VPN disconnections, WiFi dropouts, network adapter failures, or intermittent WAN connectivity issues.

Format: `NoNetConn[:<DestHost>][:NumberOfFailures]`

```powershell
.\TSS.ps1 -Netsh -WaitEvent NoNetConn  # Wait for Default Gateway to become unreachable (3 consecutive failures)
.\TSS.ps1 -NET_NCSI -WaitEvent NoNetConn:8.8.8.8:5  # Wait for 5 consecutive ping failures to 8.8.8.8
```

## Svc (Service Monitoring)

Monitors a Windows service and stops data collection when the service stops or crashes. Use the service short name (not the display name) - for example, use 'Dnscache' not 'DNS Client'. This is essential for troubleshooting service crashes, unexpected service stops, or service dependency failures. The monitoring checks the service status at each interval and triggers when the service transitions from Running to any stopped state (Stopped, Paused, or Failed). Particularly useful combined with crash dump collection (-ProcDump) to capture memory dumps of crashing services. Common scenarios include troubleshooting DHCP Client failures, DNS Client crashes, Print Spooler stops, or critical line-of-business application service failures.

Format: `Svc:<Service name>`

```powershell
.\TSS.ps1 -NET_DNScli -WaitEvent Svc:Dnscache  # Wait for DNS Client service to stop
.\TSS.ps1 -ADS_Kerb -WaitEvent Svc:KdsSvc -StopWaitTimeInSec 5  # Wait for Key Distribution Service to stop, then wait 5 more seconds
```

## Process (Process Monitoring)

Monitors a specific process and stops data collection when the process terminates (normally or abnormally). Specify process name without the .exe extension (e.g., 'Excel' not 'Excel.exe'). This is critical for troubleshooting application crashes, hangs that result in termination, or unexpected application closures. If multiple instances of the same process exist, monitoring triggers when ANY instance terminates. Extremely useful combined with crash dump collection (-ProcDump -ProcDumpAppCrash) to capture dumps of crashing applications. Common use cases include troubleshooting Office application crashes, custom application failures, browser crashes, or when applications close unexpectedly during specific operations. The monitoring polls process list at each check interval.

Format: `Process:<Process name without .exe>`

```powershell
.\TSS.ps1 -UEX_RDScli -WaitEvent Process:mstsc  # Wait for Remote Desktop client (mstsc) process to terminate
.\TSS.ps1 -UEX_AppCompat -ProcDump Excel.exe -ProcDumpAppCrash -WaitEvent Process:Excel  # Capture crash dump when Excel process terminates
```

## Share (Share Monitoring)

Monitors accessibility of a remote SMB/CIFS file share and stops data collection when the share becomes unreachable. Specify the server name (NetBIOS, FQDN, or IP) and share name. Share names with spaces must be enclosed in quotes. This is specifically designed for troubleshooting intermittent SMB access issues, file server connectivity problems, or authentication failures to shared folders. The monitoring performs actual SMB connection attempts to the share (not just ping), so it tests the complete SMB stack including authentication, server availability, and share permissions. Use this when investigating 'network path not found' errors, intermittent share access failures, or when mapped drives disconnect unexpectedly.

Format: `Share:<ServerName>:<ShareName>`

```powershell
.\TSS.ps1 -NET_SMBcli -WaitEvent Share:FileServer01:Public  # Wait for \\FileServer01\Public share to become inaccessible
```

## NetworkProtocol (Protocol Port Monitoring)

Simplified port monitoring for common protocols - automatically uses the correct port number for the specified protocol (SMB=445, HTTP=80, RDP=3389, WINRM=5985/5986). This provides a more intuitive alternative to PortDest when monitoring standard protocols. Monitors one or more remote hosts (comma-separated list) and stops when the protocol becomes unreachable on any monitored host. Particularly useful for protocol-specific troubleshooting: SMB for file server access issues, HTTP for web service connectivity, RDP for remote desktop session problems, WINRM for PowerShell remoting failures. The monitoring performs protocol-appropriate connection tests, making it more reliable than simple port checks for detecting actual service availability issues.

Format: `<SMB|HTTP|RDP|WINRM>:'<RemoteHost1,Host2>'`

```powershell
.\TSS.ps1 -NET_SMBcli -WaitEvent SMB:'server1.contoso.com'  # Wait for SMB port (445) on server1 to become unreachable
.\TSS.ps1 -UEX_RDScli -WaitEvent RDP:'10.0.0.100,10.0.0.101'  # Wait for RDP port (3389) on multiple servers to close
```

## LDAP (Domain Controller Monitoring)

Monitors LDAP connectivity to domain controllers for the specified domain and stops data collection when domain controllers become unreachable. Specify domain name (FQDN or NetBIOS name). This automatically discovers and monitors domain controllers via DNS and tests LDAP connectivity (port 389/3268). Essential for troubleshooting Active Directory connectivity issues, domain controller failures, authentication problems, or when investigating 'domain controller not available' errors. The monitoring tests actual LDAP connectivity, not just network reachability, so it validates the complete AD service stack. Use this for troubleshooting logon failures, Group Policy application issues, or intermittent AD authentication problems. Particularly valuable for distributed environments where DC availability is critical.

Format: `LDAP:<Domain name>`

```powershell
.\TSS.ps1 -ADS_Auth -WaitEvent LDAP:contoso.com  # Wait for domain controller of contoso.com to become unreachable
```

## RegData (Registry Data Monitoring)

Monitors a specific registry value's data content and stops when the data changes to (default) or from (:True) the expected value. Registry paths must start with HKLM:, HKCU:, HKCR:, or HKU: (PowerShell registry provider format). Use quotes around paths or value names containing spaces. This is powerful for troubleshooting configuration changes, group policy modifications, or application settings that get corrupted. Default behavior (:False or omitted) monitors until data changes TO the expected value - use when waiting for a configuration to be applied. With :True, monitors until data changes FROM the expected value - use when troubleshooting unwanted configuration changes. Particularly useful for tracking down what changes registry settings, monitoring for policy application, or detecting malware/script modifications to system configurations.

Format: `RegData:<RegKeyPath>:<RegValueName>:<ExpectedData>[:True]`

```powershell
.\TSS.ps1 -NET_TCP -WaitEvent RegData:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay:0x1E  # Wait until data changes TO 0x1E (30 decimal)
.\TSS.ps1 -NET_TCP -WaitEvent RegData:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay:0x1E:True  # Wait until data changes FROM 0x1E to any other value
```

## RegValue (Registry Value Monitoring)

Monitors for the creation or deletion of a specific registry value (not its data, just the value name itself). Registry paths must use PowerShell provider format (HKLM:, HKCU:, etc.). Default behavior (:False or omitted) waits for the value to be deleted/removed - useful when troubleshooting cleanup operations or when configurations get corrupted and values disappear. With :True, waits for the value to be created - useful when monitoring for configuration application, software installations, or policy deployment. This differs from RegData monitoring which watches data content changes; RegValue only cares about the existence or non-existence of the value name itself. Common scenarios include monitoring for registry value creation during software installation, detecting when applications remove their settings, or troubleshooting registry cleanup issues.

Format: `RegValue:<RegKeyPath>:<RegValueName>[:True]`

```powershell
.\TSS.ps1 -NET_TCP -WaitEvent RegValue:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay  # Wait for TcpTimedWaitDelay value to be deleted
.\TSS.ps1 -NET_TCP -WaitEvent RegValue:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay:True  # Wait for TcpTimedWaitDelay value to be created
```

## RegKey (Registry Key Monitoring)

Monitors for the creation or deletion of an entire registry key (subkey). Registry paths require PowerShell provider format (HKLM:, HKCU:, HKCR:, HKU:). Paths with spaces must be enclosed in single quotes. Default behavior (:False or omitted) waits for the key to be deleted - useful for troubleshooting when applications or services fail after their registry keys are removed, or when uninstallers don't complete properly. With :True, waits for the key to be created - useful for monitoring software installations, driver installations, or group policy application that creates new registry structures. This monitors the key container itself, not values within it. Common use cases include capturing what deletes registry keys during system cleanup, monitoring when software installs create their configuration keys, or troubleshooting group policy application that creates policy keys.

Format: `RegKey:<RegKeyPath>[:True]`

```powershell
.\TSS.ps1 -Procmon -WaitEvent RegKey:'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services':True  # Wait for registry key to be created
.\TSS.ps1 -Procmon -WaitEvent RegKey:'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -StopWaitTimeInSec 11  # Wait for registry key to be deleted, then wait 11 more seconds
```

## File (File Monitoring)

Monitors for the creation or deletion of a specific file on the local file system. Specify full path with drive letter. Paths with spaces must be enclosed in single quotes. Default behavior (:False or omitted) waits for file deletion - useful for troubleshooting when files disappear, get removed by cleanup scripts, or when investigating data loss issues. With :True, waits for file creation - useful for monitoring when applications create log files, configuration files, or output files. This is particularly powerful combined with Process Monitor (Procmon) to identify which process creates or deletes files. Common scenarios include monitoring for temporary file creation during application operations, detecting when files get deleted unexpectedly, capturing trace data around file system operations, or waiting for setup/installation logs to be created. The monitoring checks file existence at each poll interval.

Format: `File:'<FilePath>'[:True]`

```powershell
.\TSS.ps1 -ADS_Kerb -WaitEvent File:'C:\temp\TestMe.txt'  # Wait for existing file to be deleted
.\TSS.ps1 -DND_Servicing -WaitEvent File:'C:\Windows\Temp\install.log':True  # Wait for new file to be created
```

## Time (Time Elapsed Monitoring)

Simple time-based monitoring that stops data collection after a specified duration. Default unit is minutes (Min), or specify :Sec for seconds. This is the simplest monitoring option and is useful when you want to collect data for a fixed duration regardless of events. Common scenarios include collecting baseline performance data (e.g., 10 minutes of normal operation), capturing periodic issues that occur within a known timeframe, or when combined with manual reproduction steps where you know approximately how long the test will take. This is often used with performance monitoring (PerfMon, Xperf) to collect system performance data for a specific duration. Unlike other WaitEvent types that trigger on specific conditions, Time provides a guaranteed stop time regardless of system state.

Format: `Time:<N>[:Sec]`

```powershell
.\TSS.ps1 -Netsh -WaitEvent Time:5  # Wait 5 minutes then stop data collection
.\TSS.ps1 -WPR General -WaitEvent Time:300:Sec  # Wait 300 seconds (5 minutes) then stop
```

## HNSL2Tunnel (HNS Network Monitoring)

Specialized monitoring for Windows Container networking - stops when the Host Network Service (HNS) L2Tunnel virtual network is removed. This is specific to container and Hyper-V networking troubleshooting. The L2Tunnel network type is used for container networking scenarios where containers need Layer 2 network connectivity. Use this when troubleshooting Docker container networking issues, Kubernetes networking on Windows, or Hyper-V virtual switch problems. The monitoring uses Get-HNSNetwork PowerShell cmdlet to check for L2Tunnel network existence at each interval. Particularly relevant for scenarios where container networks fail or disappear unexpectedly, causing container connectivity issues. This is an advanced monitoring option typically used by Microsoft support engineers working on container platform issues.

Format: `HNSL2Tunnel`

```powershell
.\TSS.ps1 -NET_Container -WaitEvent HNSL2Tunnel -StopWaitTimeInSec 10  # Wait for HNS L2Tunnel network to disappear
```

## LogFile (Log File Monitoring)

Monitors a text-based log file for specific string patterns or regular expressions and stops when the pattern is found. Both log file path and search string must be enclosed in single quotes. The search string supports regular expressions for flexible pattern matching (e.g., 'Error.*Failed' matches 'Error: Operation Failed', 'Error - Connection Failed', etc.). This is extremely powerful for application troubleshooting where critical errors are logged to application-specific log files rather than Windows Event Logs. The monitoring reads new log entries as they're written (similar to tail -f on Linux). Common scenarios include monitoring SQL Server error logs, IIS logs, custom application logs, Java application logs, or any text-based logging. Use .* for wildcard matching in patterns. This is particularly valuable for third-party applications that don't use Windows Event Log. The search is case-insensitive by default.

Format: `LogFile:'<Path\LogfileName.ext>':'<search-string>'`

```powershell
.\TSS.ps1 -NET_SMBcli -WaitEvent LogFile:'C:\AppFolder\MyLogfileName.log':'Access.*Denied'  # Wait for 'Access Denied' or 'Access is Denied' pattern in log file
.\TSS.ps1 -SDP SQLbase -WaitEvent LogFile:'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Log\ERRORLOG':'Error: 1205'  # Wait for SQL deadlock error in error log
```

## StopCondition (Custom Script Monitoring)

Advanced monitoring option that allows you to define custom PowerShell logic to determine when to stop data collection. The condition logic is defined in the \config\StopCondition.txt file as a PowerShell script block. The script block should return $True when the stop condition is met (this signals TSS to stop data collection) or $False to keep monitoring (condition not met yet). This provides ultimate flexibility for complex monitoring scenarios not covered by built-in WaitEvent types. You can use any PowerShell commands, WMI queries, .NET methods, or custom logic. Common use cases include monitoring performance counter values, checking multiple conditions with complex boolean logic, monitoring database states, or any custom condition specific to your environment. See the StopCondition.txt file for detailed instructions, syntax examples, and sample conditions (the bundled sample stops once C:\Windows is deleted). This is the most powerful but also most complex monitoring option - use built-in WaitEvent types when possible.

Format: `StopCondition`

```powershell
.\TSS.ps1 -Scenario NET_General -WaitEvent StopCondition -StopWaitTimeInSec 15  # Wait for custom condition defined in \config\StopCondition.txt
```

## HighCPU (CPU Threshold Monitoring)

Performance-based monitoring that stops data collection when CPU usage exceeds a specified threshold for a sustained duration. By default monitors system-wide CPU usage, but can target specific process (by PID or .exe name) or service. CPU threshold is specified as percentage (1-100). The condition must persist for the duration specified by -HighCPUtimeInSec (default 10 seconds) before triggering - this prevents false triggers from brief CPU spikes. After triggering, continues collecting for -StopWaitTimeInSec duration (default 60 seconds) to capture the high CPU period. This is essential for troubleshooting CPU performance issues: system hangs due to high CPU, runaway processes, CPU spikes during specific operations, or resource exhaustion. Combine with Xperf CPU profiling or PerfMon to identify which threads/functions are consuming CPU. Use SysInternals CPUstres tool for testing. Process name must include .exe extension when targeting specific process. When a process name matches several running instances, TSS lists them and prompts for the PID to monitor; the selection is cached for the remainder of the run. The target is resolved when monitoring starts rather than when the command line is parsed, so the correct PID is used by the detached monitor of -StartNoWait and -StartAutoLogger runs, and a service that restarted in the meantime is picked up rather than a dead PID.

Format: `HighCPU:<CpuThreshold>[:<PID|ProcessName.exe|ServiceName>]`

```powershell
.\TSS.ps1 -Xperf CPU -WaitEvent HighCPU:80 -StopWaitTimeInSec 60 -HighCPUtimeInSec 20  # Stop 60 seconds after system CPU reaches 80% average for 20 seconds
.\TSS.ps1 -Xperf CPU -WaitEvent HighCPU:80:1000 -HighCPUtimeInSec 20  # Monitor PID 1000, stop after CPU reaches 80% for 20 seconds
.\TSS.ps1 -Xperf CPU -WaitEvent HighCPU:80:cpustres64.exe -HighCPUtimeInSec 20  # Monitor cpustres64.exe process
.\TSS.ps1 -Xperf CPU -WaitEvent HighCPU:80:dnscache -HighCPUtimeInSec 20  # Monitor DNS Client service (dnscache)
```

## HighMemory (Memory Threshold Monitoring)

Performance-based monitoring that stops data collection when memory consumption exceeds a specified threshold for a sustained duration. Without a target, it monitors the system memory commit charge using the '\Memory\% Committed Bytes In Use' performance counter (committed bytes relative to the system commit limit, i.e. RAM plus page file) - it is NOT a percentage of physical RAM, and only a percentage threshold is accepted. With a target, it monitors the 'Private Bytes' (private committed virtual address space) of that process, service or process group; the threshold may then be a percentage of the system commit limit or an absolute size such as 4096MB or 8GB. 'Private Bytes' is used rather than 'Working Set' because Windows trims working sets under memory pressure, so a process that is growing can show a shrinking working set exactly when the trigger is needed. When the target is a process name, every running instance of that name is summed and the instance list is refreshed on each sample, which is required for multi-process applications such as Teams, Chrome or Edge where no single process reaches the threshold although the application as a whole does; the application does not need to be running when monitoring starts, so this also works across an -StartAutoLogger reboot. The condition must persist for the duration specified by -HighMemUsageInSec (default 10 seconds) before triggering - this prevents false triggers from brief memory spikes. After triggering, continues collecting for -StopWaitTimeInSec duration (default 60 seconds) to capture the high memory period. Essential for troubleshooting memory leaks, memory exhaustion issues, out-of-memory conditions, or when system performance degrades due to low available memory. Particularly useful combined with Xperf Memory profiling, PerfMon memory counters, or memory dumps to identify which processes are consuming memory and analyze memory allocation patterns. Use this when investigating application memory leaks, pool exhaustion, or system slowdowns due to memory pressure.

Format: `HighMemory:<MemoryThreshold>[:<PID|ProcessName.exe|ServiceName>]`

```powershell
.\TSS.ps1 -Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 60 -HighMemUsageInSec 15  # Stop 60 seconds after system commit charge reaches 90% average for 15 seconds
.\TSS.ps1 -Xperf Memory -WaitEvent HighMemory:40:ms-teams.exe -HighMemUsageInSec 15  # Monitor all Teams processes combined, stop when their total Private Bytes reaches 40% of the system commit limit
.\TSS.ps1 -Xperf Memory -WaitEvent HighMemory:4096MB:ms-teams.exe  # Monitor all Teams processes combined, stop when their total Private Bytes reaches 4096 MB
.\TSS.ps1 -Xperf Memory -WaitEvent HighMemory:8GB:1000  # Monitor PID 1000 only, stop when its Private Bytes reaches 8 GB
```

## PerfCounter (Performance Counter Threshold Monitoring)

Generic performance-based monitoring that stops data collection when any Windows performance counter stays at or above a specified threshold for a sustained duration. Unlike HighCPU and HighMemory, which are bound to fixed counters and compare the AVERAGE over the sampling window, PerfCounter accepts an arbitrary counter path and requires EVERY sample within the duration to clear the threshold - a brief spike does not trigger. The counter is sampled once per second, so -PerfCounterInSec (default 5 seconds) also determines the number of samples taken per poll. This strict check suits steady-state gauge counters such as session or queue counts; volatile rate and percentage counters may fluctuate below the threshold between samples and therefore may not trigger reliably. After triggering, continues collecting for -StopWaitTimeInSec duration (default 60 seconds) to capture the period of interest. Essential for scenarios where the repro condition is visible in Perfmon but has no corresponding event log entry, for example LDAP client session pile-up on a domain controller, queue depth growth, or handle and thread count runaway. Counter names are localized, so on a non-English operating system the localized counter path must be used - run 'Get-Counter -ListSet * | Select-Object -ExpandProperty Paths' to find the correct name.

Format: `PerfCounter:<CounterPath>[:<Threshold>]`

```powershell
.\TSS.ps1 -NET_LDAPsrv -WaitEvent PerfCounter:'\DirectoryServices(*)\Ldap Client Sessions':5000 -PerfCounterInSec 5 -StopWaitTimeInSec 60  # Stop 60 seconds after LDAP client sessions stay at or above 5000 for 5 seconds
.\TSS.ps1 -PerfMon General -WaitEvent PerfCounter:'\LogicalDisk(C:)\% Disk Read Time':50 -PerfCounterInSec 10  # Counter path contains a colon, so it is enclosed in single quotes inside the double-quoted argument
```

## Signal (Named Signal Monitoring)

Monitors for a manual signal sent using the Windows built-in WAITFOR.exe command with /SI parameter. This provides a simple mechanism for manually triggering trace stops from another command prompt, script, or scheduled task. The signal string is case-sensitive. To stop traces, open a command prompt and run: WAITFOR.exe /SI <SignalString> (must match exactly). This is useful when you need manual control over when traces stop but don't want to use Ctrl+C, or when another script/application needs to signal TSS to stop. Currently limited to local machine only (signals from remote machines are not supported). Common scenarios include coordinating trace stops with other automated processes, allowing operators to stop traces via predefined commands, or integration with monitoring systems that can execute commands. Internally TSS performs a one-time blocking wait by running 'WAITFOR.exe <SignalString>' (no timeout); it returns and stops as soon as the named signal is received.

Format: `Signal:<SignalString>`

```powershell
.\TSS.ps1 -Netsh -WaitEvent Signal:MyStopSignal -StopWaitTimeInSec 10  # Wait for signal 'MyStopSignal' (sent via: WAITFOR.exe /SI MyStopSignal)
```

## ATQ (ATQ Thread Exhaustion Monitoring)

Specialized Active Directory monitoring that detects ATQ (Asynchronous Thread Queue) thread pool exhaustion on Domain Controllers. ATQ thread exhaustion occurs when NTDS (running inside LSASS) runs out of available threads to process LDAP requests, causing the domain controller to stop responding to LDAP/authentication queries. This is a critical condition that can cause widespread authentication failures, GPO application issues, and domain controller performance problems. The monitoring samples the NTDS ATQ thread performance counters and signals when the used threads ('\DirectoryServices(NTDS)\ATQ Threads LDAP' + '\DirectoryServices(NTDS)\ATQ Threads Other') equal the total ('\DirectoryServices(NTDS)\ATQ Threads Total'), i.e. no ATQ threads remain free. This is typically used only when troubleshooting known ATQ exhaustion issues on Domain Controllers - it's not a general-purpose monitoring option. When triggered, should be combined with comprehensive AD tracing (-ADS_LDAPsrv, -ADS_SAMsrv, etc.) to capture the conditions leading to thread exhaustion. This is an advanced domain controller troubleshooting option primarily used by Active Directory support engineers.

Format: `ATQ`

```powershell
.\TSS.ps1 -ADS_LDAPsrv -WaitEvent ATQ -StopWaitTimeInSec 30  # Wait for ATQ thread exhaustion on Domain Controller
```

## Permission (Permission/ACL Change Monitoring)

Monitors Access Control Lists (ACLs) on files, folders, or registry keys and stops when permissions/ACLs are modified. Specify full path to the object to monitor - supports file system paths (e.g., C:\Windows) and registry paths (HKLM:\SOFTWARE\...). Paths with spaces must be enclosed in single quotes. This is critical for security troubleshooting: detecting unauthorized permission changes, tracking down what modifies ACLs on sensitive files/folders, investigating 'access denied' errors that appear after permission changes, or monitoring for malware that modifies security settings. The monitoring uses Get-Acl to capture and compare ACL states at each poll interval. Particularly powerful combined with Process Monitor (Procmon) to identify which process/user is modifying permissions. Common scenarios include troubleshooting permission inheritance issues, detecting when applications or scripts modify folder security, or investigating ransomware that changes file permissions. Works with both NTFS file system ACLs and registry key security descriptors.

Format: `Permission:'<File-Path>|<Folder-Path>|<Registry-Path>'`

```powershell
.\TSS.ps1 -UEX_FSLogix -WaitEvent Permission:'C:\Windows' -StopWaitTimeInSec 10  # Wait for permission change on C:\Windows folder
.\TSS.ps1 -UEX_FSLogix -WaitEvent Permission:'C:\Temp\Test1.txt'  # Wait for permission change on specific file
.\TSS.ps1 -Procmon -WaitEvent Permission:'HKLM:\SOFTWARE\Microsoft\CESDiagnosticTools\TSS'  # Wait for permission change on registry key
```

## Crash (Crash Trigger)

NOT a standalone WaitEvent type - this is a modifier flag that forces a system crash dump after ANY other WaitEvent is triggered. **WARNING: System will immediately reboot and all unsaved work will be lost.** Used when you need a complete system memory dump to analyze the exact system state when an issue occurs. Specify crash dump type with -CrashMode: 'full' (complete physical memory, largest file), 'kernel' (kernel memory only, recommended default), 'mini' (smallest, limited information), 'active' (active memory pages only), or 'automatic' (system decides based on available disk space). This is typically reserved for severe issues like system hangs, blue screens, deadlocks, or situations where other diagnostic data is insufficient. The crash is triggered via NotMyFault.sys driver or Registry-based crash trigger. Requires administrative privileges and sufficient disk space for dump file. Use this as last resort when all other diagnostic methods have failed to capture the issue - system crashes are disruptive and should be carefully planned.

Format: `-WaitEvent <EventType> -Crash [-CrashMode <active|automatic|full|kernel|mini>]`

```powershell
.\TSS.ps1 -NET_SMBsrv -WaitEvent Evt:1234:'System' -Crash -CrashMode kernel  # Generate kernel dump when Event 1234 is logged, then reboot
```

