# Microsoft Entra ID

<!-- pack:start -->
5 rules, 2 Building Blocks.

**Log source types:** Microsoft Entra ID

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| EntraID - Federated Domain Modified | Rule | 7 | T1484.002 |
| EntraID - MFA Bypass via Trusted IP Detected | Rule | 7 | T1556.006 |
| EntraID - MFA Removed for User Account | Rule | 4 | T1556.006 |
| EntraID - Password Spray Attack Detected | Rule | 4 | T1110.003 |
| EntraID - Privileged Role Assigned to User | Rule | 7 | T1098.003 |
| BB:EntraID - Password Spray IPv4 | BB | - | - |
| BB:EntraID - Password Spray IPv6 | BB | - | - |

**Custom properties** the console must have:

- Error Code (custom)
- OAuth Actor (custom)
- Role Name (custom)
<!-- pack:end -->
