# Fortinet FortiGate

<!-- pack:start -->
17 rules, 20 Building Blocks.

**Log source types:** Fortinet FortiGate Security Gateway

| Rule | Type | Severity | MITRE ATT&CK |
|---|---|---|---|
| FW - AD Traffic Flow via Internet | Rule | 4 | T1133 |
| FW - Active Directory Web Services Port Activity | Rule | 4 | T1078.002 |
| FW - Allowed Traffic on Common C2 Ports | Rule | 7 | T1571 |
| FW - External External Scan | Rule | 2 | T1595 |
| FW - High Severity IDS or IPS Alert | Rule | 7 | - |
| FW - Internal ICMP Sweep Detection | Rule | 4 | T1018 |
| FW - Internal Remote Tool Discovery | Rule | 4 | T1046, T1219 |
| FW - Internal UDP Scanner | Rule | 2 | T1046 |
| FW - Internet Exposed SNMP Service | Rule | 4 | T1602.001 |
| FW - Local TCP Scanner Detected | Rule | 7 | T1046 |
| FW - Potential Local Destination IP Scan | Rule | 2 | T1018 |
| FW - Potential Local Port Scan | Rule | 2 | T1046 |
| FW - RPC to or from the Internet | Rule | 4 | T1190 |
| FW - Remote Modify Firewall | Rule | 7 | T1562.004 |
| FW - SMB to the Internet | Rule | 2 | T1048 |
| FW - Suspicious SSH Access | Rule | 4 | T1021.004 |
| FW - Vulnerable Protocol Usage | Rule | 4 | T1557 |
| BB:FW - DHCP Scanner | BB | - | - |
| BB:FW - DNS Scanner | BB | - | - |
| BB:FW - Database Scanner | BB | - | - |
| BB:FW - FTP Scanner | BB | - | - |
| BB:FW - IM Server Scanner | BB | - | - |
| BB:FW - IRC Server Scanner | BB | - | - |
| BB:FW - LDAP Server Scanner | BB | - | - |
| BB:FW - Mail Server Scanner | BB | - | - |
| BB:FW - P2P Server Scanner | BB | - | - |
| BB:FW - Proxy Server Scanner | BB | - | - |
| BB:FW - RMM Ports | BB | - | - |
| BB:FW - RPC Server Scanner | BB | - | - |
| BB:FW - Remote Shell Ports | BB | - | - |
| BB:FW - SMB Scanner | BB | - | - |
| BB:FW - SNMP Scanner | BB | - | - |
| BB:FW - SSH Server Scanner | BB | - | - |
| BB:FW - Uncommon Port Scanner | BB | - | - |
| BB:FW - Unsecure TCP Ports | BB | - | - |
| BB:FW - Web Server Scanner | BB | - | - |
| BB:FW - Windows Server Scanner | BB | - | - |

**Custom properties** the console must have:

- Action (custom)
- Level (custom)
- OS Name (custom)
- Policy Type (custom)
- Threat Severity (custom)

**Reference sets** (created empty by the extension unless `reference-data.yml` fills them):

- (Shared) Avast - IP
- (Shared) misp_dstip - IP
- (Shared) misp_srcip - IP
- FW - Trusted Admin Networks - CIDR

**IBM content extensions** the console must have:

- User Behavior Analytics Endpoint Content 5.1.0: BB:PortDefinition: TFTP Ports
<!-- pack:end -->
