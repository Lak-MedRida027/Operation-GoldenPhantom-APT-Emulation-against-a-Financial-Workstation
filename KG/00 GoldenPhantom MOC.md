---
type: moc
tags:
  - moc
---

# Operation GoldenPhantom — Map of Content
Central index. Open the **Graph view** to see the full kill chain.

## Kill chain (UTC)
[[T1078 Valid Accounts]] -> [[T1562.001 Disable Tools]] -> [[T1105 Ingress Tool Transfer]] ->
[[T1036.005 Masquerading]] -> [[T1071.001 Web Protocols]] -> [[T1059.001 PowerShell]] ->
[[T1566.001 Phishing Attachment]] -> [[T1068 Privilege Escalation]] ->
[[T1003.001 LSASS Dumping]] -> [[T1562.004 Disable Firewall]] -> [[T1112 Modify Registry]] ->
[[T1543.003 Windows Service]] -> [[T1046 Network Service Discovery]] ->
[[T1087.001 Local Account Discovery]] -> [[T1048.003 Exfiltration]]

## Entities
- Host: [[DESKTOP-2A1O8LD]] · User: [[anmar]] · Actor: [[GoldenPhantom Actor]]
- Infra: [[Caldera C2 Server]] · [[example.com Exfil]]
- Tools: [[Sandcat Agent]] · [[Invoke-Mimikatz]] · [[PowerUp]] · [[splunkd.exe masquerade]] · [[update.exe service binary]]

## Negative findings
[[T1558.001 Golden Ticket]] · [[T1003.006 DCSync]] · [[T1558.003 Kerberoasting]] — all impossible on WORKGROUP.
