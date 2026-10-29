# Microsoft Office 365

The Microsoft Office 365 DSM is built into QRadar. The custom properties below come with these
IBM content extensions:

- IBM QRadar Custom Properties Dictionary
- IBM QRadar Custom Properties for Office 365
- IBM Security QRadar Content Extension for Hybrid Cloud Use Cases

<!-- pack:start -->
7 rules, 0 Building Blocks.

**Log source types:** Microsoft Office 365

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| O365 - Azure AD New Service Principal Credentials | Rule | 2 | T1098.001 |
| O365 - Exchange Mailbox Audit Logging Bypass | Rule | 7 | T1562.008 |
| O365 - Exchange Suspicious Email Forwarding | Rule | 4 | T1114.003 |
| O365 - Mailbox Forwarding Rule Configured | Rule | 2 | T1114.003 |
| O365 - Mailbox Full Access Permission Granted | Rule | 2 | T1098.002 |
| O365 - Member Added to High-Severity Entra ID Group | Rule | 7 | T1098.003 |
| O365 - Permission Grant to Azure Application | Rule | 4 | T1528 |

**Custom properties** the console must have:

| Property | IBM package | Parsed for this log source |
|---|---|---|
| Action (custom) | IBM QRadar Custom Properties Dictionary 1.4.1<br>IBM QRadar Custom Properties for Cisco Firepower (Syslog) 1.0.1 | no: needs an expression for Microsoft Office 365 |
| Action Type (custom) | not in IBM extensions: create it on the console | - |
| Affected Workload (custom) | IBM Security QRadar Custom Properties for Office 365 1.4.1 | yes |
| Group Name (custom) | IBM Security QRadar Custom Properties for Office 365 1.4.1 | yes |
| Object Name (custom) | IBM QRadar Custom Properties Dictionary 1.4.1<br>IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | no: needs an expression for Microsoft Office 365 |
| Sender (custom) | IBM QRadar Custom Properties Dictionary 1.4.1 | no: needs an expression for Microsoft Office 365 |
| Target Username (custom) | IBM Security QRadar Custom Properties for Office 365 1.4.1 | yes |
| User Right (custom) | IBM QRadar Custom Properties Dictionary 1.4.1<br>IBM QRadar Custom Properties for Microsoft Windows 1.2.9 | no: needs an expression for Microsoft Office 365 |

**Reference sets** (created empty by the extension unless `reference-data.yml` fills them):

- (Shared) Entra High Groups - AlphaNumeric
<!-- pack:end -->
