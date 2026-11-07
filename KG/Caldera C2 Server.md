---
type: infra
tags:
  - infra
---

# Infrastructure — Caldera C2 Server
- 192.168.67.128 : TCP **8888**
- Banner: `Server: Python/3.13 aiohttp/3.14.1`
- Endpoints: `/beacon`, `/file/download`
- Plaintext HTTP with base64 JSON bodies -> fully recoverable.

## Related
- [[Sandcat Agent]]
- [[T1071.001 Web Protocols]]
- [[T1105 Ingress Tool Transfer]]
- [[Evidence PCAP beacon]]
