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

- Authentication Package (custom)
- Command (custom)
- Impersonation Level (custom)
- Logon Process (custom)
- Logon Type (custom)
- Machine Identifier (custom)
- Parent Command (custom)
- Parent Process Name (custom)
- Parent Process Path (custom)
- Process Name (custom)
- Process Path (custom)
- Task Name (custom)

**Properties in AQL filters** (custom or built-in): Account Name, Account Security ID, AllowHardTerminate, Command Arguments, File Path, Filename, Logon Account Domain, Logon Account Name, Registry Key
<!-- pack:end -->
