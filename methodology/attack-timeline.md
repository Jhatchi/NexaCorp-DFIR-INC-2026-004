# Attack Timeline: INC-2026-004

Reference: BCC-2026 / INC-2026-004. Target: bru-web-01.

All times in local server time (UTC+02:00, CEST), taken from `web_access.log` (HTTP activity) and `auth.log` (SSH consequence). `web_access.log` is the authoritative source for exact request times. Source IP for every malicious entry: `172.16.50.10`.

## Phase 1 to 2: web exploitation (from web_access.log and attack.pcap)

| Time | Action | Payload or evidence | Phase |
| ---- | ------ | ------------------- | ----- |
| 09:35:02 | Reconnaissance, error-based probe | `id=1'` | Confirm vulnerability |
| 09:35:02 | Probe continued | `id=1''` | Confirm vulnerability |
| 09:35:02 | Boolean probe | `id=1' OR '1'='1` | Confirm vulnerability |
| 09:37:24 | Column counting | `ORDER BY 1` (HTTP 200) | Map query |
| 09:37:26 | Column counting | `ORDER BY 2` (HTTP 200) | Map query |
| 09:37:27 | Column counting | `ORDER BY 3` (HTTP 500) -> query has 2 columns | Map query |
| 09:37:28 | UNION confirmed | `UNION SELECT NULL,NULL` | Map query |
| 09:37:30 | Engine fingerprint | `UNION SELECT NULL,@@version` | Enumerate |
| 09:38:29 | Database name | `UNION SELECT NULL,database()` -> `dvwa` (PCAP stream 14) | Enumerate |
| 09:38:30 | Table enumeration | `information_schema.tables WHERE table_schema=database()` | Enumerate |
| 09:38:33 | Column enumeration | `information_schema.columns WHERE table_name='users'` | Enumerate |
| 09:38:34 | Row count | `count(*) FROM users` | Enumerate |
| 09:39:58 | **Data exfiltration** | `UNION SELECT user,password FROM users` (response 5745, PCAP stream 447) | **Dump** |
| 09:39:58 to 09:40:00 | Targeted per-account dumps | `WHERE user='admin'`, `'j.martin'`, `'gordonb'`, `'pablo'`, `'smithy'` | Dump |
| 09:41:38 onward | Blind boolean extraction | `AND SUBSTRING(password,N,1)='x'` (noisiest phase) | Blind enum |

## Offline (no server log)

| Time | Action | Evidence |
| ---- | ------ | -------- |
| between 09:39:58 and 14:48:06 | Offline cracking of `j.martin` MD5 hash | No server log. Recovered `[REDACTED-lab-credential]` in under 1s against rockyou |

## Phase 4: consequence (from auth.log)

| Time | Action | Evidence |
| ---- | ------ | -------- |
| 14:48:06 | **Successful SSH login** as `j.martin` from `172.16.50.10` | `Accepted password for j.martin ... uid=1001` |
| 14:48:06 | Session opened, then closed shortly after | `session opened` / `session closed` for j.martin |
| 14:48:27 onward | Failed SSH retries for j.martin | `Failed password for j.martin` |
| 14:49:02 onward | Credential spraying of other dumped accounts | `Invalid user admin`, `Invalid user gordonb`, all failed |

## Reading the timeline

The exploitation phase is compressed into roughly six minutes (09:35 to 09:41). The successful SSH foothold lands about five hours later at 14:48, the gap being the offline crack window. The exfiltration anchor for any timeline question is 09:39:58, taken from the access log, not from the SIEM import time.
