# Sysmon

<!-- pack:start -->
15 rules, 0 Building Blocks.

**Log source types:** Microsoft Windows Security Event Log

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| Sysmon - Executables Started in Suspicious Folder | Rule | 4 | T1036 |
| Sysmon - Indirect Command Execution via External Tool | Rule | 7 | T1202, T1216.002 |
| Sysmon - Ingress Tool Transfer via System Utility | Rule | 7 | T1105 |
| Sysmon - LSASS Credentials Dump from Memory | Rule | 7 | T1003.001 |
| Sysmon - Mshta.exe Suspicious File Load | Rule | 4 | T1218.005 |
| Sysmon - NTDS.dit Domain Hash Retrieval Activity | Rule | 7 | T1003.003, T1003.002 |
| Sysmon - New WMI Event Subscription | Rule | 4 | T1546.003 |
| Sysmon - Persistence via Registry Run Keys | Rule | 4 | T1547.001 |
| Sysmon - Process Spawn from WScript | Rule | 4 | T1059.005, T1059.007 |
| Sysmon - Remote Execution via SMB Share | Rule | 4 | T1021.002 |
| Sysmon - Remote Thread Creation inside System Process | Rule | 7 | T1055 |
| Sysmon - Rogue Windows System Process | Rule | 7 | T1036.005 |
| Sysmon - Script Execution from Office Application | Rule | 4 | T1566.001, T1204.002 |
| Sysmon - System Binary Proxy via Control Panel Items | Rule | 4 | T1218.002 |
| Sysmon - Unload of Sysmon Driver | Rule | 7 | T1562.001 |

**Custom properties** the console must have:

| Property | IBM package | Parsed for this log source |
|---|---|---|
| Command (custom) | IBM QRadar Content Extension for Sysmon 1.3.2<br>IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>User Behavior Analytics Endpoint Content 5.1.0 | yes |
| Granted Access (custom) | IBM QRadar Content Extension for Sysmon 1.3.2 | yes |
| Machine Identifier (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Parent Process Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Process Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>IBM QRadar Security Threat Monitoring Content Extension 3.1.0<br>User Behavior Analytics Endpoint Content 5.1.0 | yes |
| Process Path (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Registry Value Data (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Registry Value Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Source Process Path (custom) | IBM QRadar Custom Properties Dictionary 1.4.1 | no: needs an expression for Microsoft Windows Security Event Log |
| Target Object (custom) | IBM QRadar Content Extension for Sysmon 1.3.2 | yes |
| Target Process Name (custom) | IBM QRadar Content Extension for Sysmon 1.3.2 | yes |
| Target Process Path (custom) | IBM QRadar Content Extension for Sysmon 1.3.2 | yes |

**Properties in AQL filters** (custom or built-in): Current Directory, Description, Event ID, Original Filename, Process CommandLine
<!-- pack:end -->
