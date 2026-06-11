# IOC Summary - INC-2026-004

Reference: BCC-2026 / INC-2026-004.

**Lab-local artifacts only.** These indicators come from a fictitious BeCode lab scenario. Do not ingest them into a production SIEM as real-world threat intelligence.

## A. Network indicators

| Type | Value | Context |
| ---- | ----- | ------- |
| Source IP | `172.16.50.10` | Attacker, sole source outside the internal `192.168.10.0/24` range |
| Target host | `bru-web-01` (192.168.10.20) | Employee self-service portal |

## B. Web payload signatures

| Pattern | Meaning |
| ------- | ------- |
| `%27` (`'`) | Single-quote probe, error-based confirmation |
| `ORDER BY n` | Column counting |
| `UNION SELECT` | UNION-based data extraction |
| `database()` | Current database name enumeration |
| `information_schema` | Schema and table mapping |
| `FROM users` | Direct dump of the users table |
| `SUBSTRING(password,N,1)=` | Blind boolean extraction |

Targeted endpoint: `/dvwa/vulnerabilities/sqli/`, parameter `id`.

## C. Exposed data

| Type | Value |
| ---- | ----- |
| Database name | `dvwa` |
| Compromised account | `j.martin` (uid 1001) |
| Exposed MD5 hash | `ccf5538dc31d435d6bab145c924041d8` |
| Recovered password | `P@ssw0rd123` |
| Other exposed accounts | admin, gordonb, 1337, pablo, smithy (DVWA defaults) |

## D. Host artifacts (consequence)

| Type | Value |
| ---- | ----- |
| Service abused | SSH (sshd) on bru-web-01 |
| Successful login | `Accepted password for j.martin from 172.16.50.10`, 2026-05-30 14:48:06 (+02:00) |
| Failed sprays | j.martin (retry), admin, gordonb from the same IP |

## E. Detection note

A SIEM or IDS rule keying on `UNION SELECT`, `information_schema`, or a lone `%27` in the request URI from a non-internal source would have flagged this attack in real time. The corresponding Wazuh alert in the bundle is rule 31103 (web attack, injection attempt). The full Suricata detection ruleset is a planned v2 deliverable (see repository Roadmap).
