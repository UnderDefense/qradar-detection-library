# Active Directory

<!-- pack:start -->
2 rules, 2 Building Blocks.

**Log source types:** Microsoft Windows Security Event Log

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| AD - Multiple Login Failures for Single Username | Rule | 2 | T1110 |
| AD - Potential Bruteforce from Single User | Rule | - | T1110.001 |
| BB:AD - Invalid Password at Login | BB | - | - |
| BB:AD - Password Expired at Login | BB | - | - |

**Custom properties** the console must have:

- Extended Error Code (custom)

**Properties in AQL filters** (custom or built-in): Authentication Package, Logon Account Domain, Logon Account Name, Logon Type, Machine Identifier

**Reference sets** (created empty by the extension unless `reference-data.yml` fills them):

- (Shared) Brute Force exclusion - IP
- (Shared) Password Change - AlphaNumeric
<!-- pack:end -->
