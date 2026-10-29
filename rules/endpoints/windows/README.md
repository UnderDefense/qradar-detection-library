# Windows Security Event Log

<!-- pack:start -->
4 rules, 2 Building Blocks.

**Log source types:** Microsoft Windows Security Event Log

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| Windows - Access Token Abuse | Rule | 4 | T1134.001 |
| Windows - Credential Dumping via Registry | Rule | 7 | T1003.002, T1552.002 |
| Windows - Scheduled Task Created on Multiple Hosts | Rule | 4 | T1053.005 |
| Windows - Suspicious Double Extension | Rule | 4 | T1036.007 |
| BB:Windows - Scheduled Task Creation | BB | - | - |
| BB:Windows - Scheduled Task Creation by a Process | BB | - | - |

**Custom properties** the console must have:

| Property | IBM package | Parsed for this log source |
|---|---|---|
| Authentication Package (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>User Behavior Analytics Domain Controller Content 5.1.0 | yes |
| Command (custom) | IBM QRadar Content Extension for Sysmon 1.3.2<br>IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>User Behavior Analytics Endpoint Content 5.1.0 | yes |
| Impersonation Level (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Logon Process (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Logon Type (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>User Behavior Analytics Access and Authentication Content 5.1.0<br>User Behavior Analytics Domain Controller Content 5.1.0 | yes |
| Machine Identifier (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Parent Command (custom) | IBM QRadar Content Extension for Sysmon 1.3.2<br>IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Parent Process Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Parent Process Path (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Process Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9<br>IBM QRadar Security Threat Monitoring Content Extension 3.1.0<br>User Behavior Analytics Endpoint Content 5.1.0 | yes |
| Process Path (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |
| Task Name (custom) | IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | yes |

**Properties in AQL filters** (custom or built-in): Account Name, Account Security ID, AllowHardTerminate, Command Arguments, File Path, Filename, Logon Account Domain, Logon Account Name, Registry Key
<!-- pack:end -->
