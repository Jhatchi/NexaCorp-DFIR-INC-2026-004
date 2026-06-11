# INC-2026-004 Findings Report

**Engagement:** NexaCorp DFIR, SQL Injection Investigation
**Reference:** BCC-2026 / INC-2026-004
**Target system:** bru-web-01, NexaCorp employee self-service portal
**Reported by:** Marc Wauters, IT Infrastructure Manager
**Date reported:** 2026-06-02
**Analyst:** Johan-Emmanuel Hatchi, SOC Analyst L1, BeCode Corp
**Delivered:** 2026-06-11
**Classification:** Confidential

> All timestamps use the web server local time zone (UTC+02:00), which matches `web_access.log`, the authoritative request record. The PCAP capture window (`README.txt`) is expressed in UTC: 2026-05-30 07:34:03Z to 14:14:55Z.

---

## 1. Plain-language summary

Someone outside the company found a weak spot in the staff portal and used it to read the company database through the web page itself. They pulled out the list of user accounts and their scrambled passwords. One staff account, `j.martin`, had a password weak enough to be unscrambled in seconds on an ordinary laptop.

A few hours later, that same outsider used the recovered password to log in to the server directly, and it worked. They now have a working login on the server, using a real employee's identity. Every password stored in the portal should be considered exposed. The portal code needs a fix so this cannot happen again, and the compromised account must be locked immediately.

## 2. Executive summary

An external attacker (`172.16.50.10`) exploited a SQL Injection vulnerability in the `id` parameter of the NexaCorp employee portal (`bru-web-01`). The attacker confirmed the flaw with an error-based probe, mapped the database, and exfiltrated the full `users` table, including six accounts and their MD5 password hashes. The employee account `j.martin` used the password `P@ssw0rd123`, recovered offline in under one second against a standard wordlist.

Approximately five hours later, the attacker reused that credential to authenticate over SSH to the same server and succeeded, then attempted to spray the other stolen accounts (which failed). The outcome is a confirmed authenticated foothold on `bru-web-01` and the exposure of every credential in the portal database. Immediate remediation is required.

## 3. Scope and methodology

Forensic analysis of the evidence bundle only, covering four phases: web access log analysis, PCAP response analysis, SIEM alert review, and consequence analysis. The investigation follows NIST SP 800-61r2 (Detection & Analysis), SANS PICERL (Identification), and maps every finding to MITRE ATT&CK Enterprise v15. The root vulnerability is classified under OWASP A03:2021 Injection.

**Evidence sources:** `logs/web_access.log` (1342 requests total), `attack.pcap`, `wazuh-alerts.json`, `logs/auth.log`.

## 4. Findings

### Finding 4.1 - SQL Injection on the `id` parameter

| | |
| --- | --- |
| **Severity** | 🔴 CRITICAL |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **Affected asset** | `bru-web-01`, endpoint `/dvwa/vulnerabilities/sqli/`, parameter `id` |

**Description.** The `id` parameter passes user input directly into a back-end SQL query without separating data from instructions. The attacker confirmed and exploited this, escalating from a simple probe to full database read access.

**Evidence.** The attack chain is visible in the access log in the following order:

- `09:35:02` error-based probe: `id=1'`, then `1''`, then `1' OR '1'='1`. A lone single quote breaks the query and forces a database error, confirming the field is injectable.
- `09:37:24` to `09:37:27` column counting: `ORDER BY 1`, `2` return HTTP 200, `ORDER BY 3` returns HTTP 500. The query returns exactly 2 columns.
- `09:37:28` onward UNION exploitation: `UNION SELECT NULL,NULL`, then `@@version`, `database()`, and `information_schema` queries to map the engine, the database, and the `users` table.

**Impact.** Full read access to the back-end database through the public-facing portal.

**Remediation.** Replace the query with parameterized queries (prepared statements). Add server-side input validation on `id`.

### Finding 4.2 - Database enumeration and full `users` table exfiltration

| | |
| --- | --- |
| **Severity** | 🟠 HIGH |
| **MITRE ATT&CK** | T1213 (Data from Information Repositories) |
| **Affected asset** | `dvwa` database on `bru-web-01` |

**Description.** Using the confirmed UNION injection, the attacker read the database name and dumped the complete `users` table, exposing every username and password hash.

**Evidence.** The server responses, recovered from the PCAP via Follow HTTP Stream:

- TCP stream 14: the `database()` payload returns the database name `dvwa`.
- TCP stream 447: `UNION SELECT user,password FROM users` returns the full table (response size 5745, the largest of the session). Six accounts were exposed:

| Username | MD5 hash | Note |
| -------- | -------- | ---- |
| admin | `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 of `password` |
| gordonb | `e99a18c428cb38d5f260853678922e03` | application default |
| 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | application default |
| pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | application default |
| smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 of `password` |
| **j.martin** | **`ccf5538dc31d435d6bab145c924041d8`** | NexaCorp employee account |

**Exfiltration time:** 2026-05-30 09:39:58 (+02:00). This is the moment the data left the database.

**Impact.** Every credential stored in the portal database is exposed. The account of operational concern is `j.martin`, the only one matching a real employee naming pattern and the only one the attacker re-queried by name.

**Remediation.** Treat every account in the table as compromised and force a reset. Fix the underlying injection (see 4.1).

### Finding 4.3 - Weak credential recovered offline

| | |
| --- | --- |
| **Severity** | 🟠 HIGH |
| **MITRE ATT&CK** | T1110.002 (Brute Force: Password Cracking) |
| **Affected asset** | account `j.martin` |

**Description.** The MD5 hash of `j.martin` was recovered offline against the standard `rockyou.txt` wordlist using John the Ripper, on the analyst workstation, never against the live server. The recovery took under one second.

**Evidence.** Hash `ccf5538dc31d435d6bab145c924041d8` resolves to cleartext `P@ssw0rd123`.

**Analysis.** `P@ssw0rd123` satisfies a typical complexity policy (upper case, lower case, digit, special character, 11 characters) yet falls instantly, because the pattern is common and present in standard wordlists. Syntactic complexity is not the same as resistance to guessing.

**Remediation.** Block common and predictable passwords by checking new passwords against a known-breached list. Enforce multi-factor authentication. Migrate password storage away from unsalted MD5 toward a slow, salted hash (bcrypt or argon2).

### Finding 4.4 - Credential reuse, successful SSH foothold

| | |
| --- | --- |
| **Severity** | 🔴 CRITICAL |
| **MITRE ATT&CK** | T1078 (Valid Accounts), T1021.004 (Remote Services: SSH) |
| **Affected asset** | `bru-web-01` (SSH service) |

**Description.** The stolen and cracked credential was reused against SSH on the same server. The login succeeded, giving the attacker an authenticated foothold under a legitimate employee identity.

**Evidence.** From `auth.log`:

```
2026-05-30T14:48:06 bru-web-01 sshd[14736]: Accepted password for j.martin from 172.16.50.10 port 49145 ssh2
session opened for user j.martin(uid=1001)
```

The successful login at 14:48:06 came from the same IP used for the SQL Injection. Immediately after, the attacker attempted to spray other dumped accounts (j.martin retry, admin, gordonb), all of which failed. The gap between the dump (09:39:58) and the successful SSH login (14:48:06) is about five hours, consistent with offline cracking before reuse.

**Impact.** A confirmed interactive foothold on the server under a real employee identity. This access is the entry point for follow-on activity.

**Remediation.** Disable or reset `j.martin` immediately and terminate any active sessions. Enforce MFA on SSH, restrict SSH to the internal network or VPN, and add lockout or rate limiting against spraying. Block `172.16.50.10`.

## 5. Indicators of Compromise

See [`evidence-summary/ioc-summary.md`](../evidence-summary/ioc-summary.md) for the SIEM-ingestible list. Summary:

- Attacker IP: `172.16.50.10`
- Targeted endpoint: `/dvwa/vulnerabilities/sqli/`, parameter `id`
- Payload patterns: `%27`, `ORDER BY`, `UNION SELECT`, `database()`, `information_schema`, `FROM users`, `SUBSTRING(password,...)`
- Compromised account: `j.martin` (uid 1001), password `P@ssw0rd123`
- Consequence: successful SSH login, 2026-05-30 14:48:06 (+02:00)

## 6. Timeline

The full minute-by-minute timeline is in [`methodology/attack-timeline.md`](../methodology/attack-timeline.md). Key anchors:

| Time (+02:00) | Event |
| ------------- | ----- |
| 09:35:02 | Error-based probe (single quote) |
| 09:37:27 | Column count confirmed (2) via ORDER BY 3 returning HTTP 500 |
| 09:38:29 | Database name read: `dvwa` |
| 09:39:58 | Full `users` table exfiltrated (exfiltration anchor) |
| 09:41:38 | Blind boolean probing |
| 14:48:06 | Successful SSH login as `j.martin` from the attacker IP |

## 7. Remediation recommendations (prioritised)

**P0, immediate (within hours):**

1. Disable or reset `j.martin` and terminate active sessions. The attacker holds valid SSH access.
2. Block `172.16.50.10` at the perimeter.
3. Force a password reset for every account in the dumped `users` table.

**P1, short term (within days):**

4. Fix the root cause: parameterized queries on the `id` parameter, plus input validation.
5. Harden SSH: MFA, restrict to internal or VPN, lockout against spraying.
6. Enforce a real password policy that blocks common and breached passwords.

**P2, medium term:**

7. Migrate password storage from unsalted MD5 to bcrypt or argon2.
8. Deploy detection (IDS or WAF rules) that alert on SQL Injection patterns in the request URI. Four validated Suricata signatures covering the techniques seen in this incident are provided in the `detection/` folder of this repository.
9. Review network segmentation: external SSH to `bru-web-01` should not be reachable.

## 8. Detection engineering

After the investigation reconstructed the attack, four Suricata signatures were written to detect each SQL injection technique observed, then validated by replaying the capture offline (`suricata -r attack.pcap`). The host had no default ruleset, so the baseline was zero alerts and every count below comes from these four local rules. Each rule inspects the normalized `http.uri` buffer, so URL-encoded payloads are matched in decoded form.

| SID | Detection | Technique | MITRE ATT&CK | Alerts |
|-----|-----------|-----------|--------------|--------|
| 1000001 | UNION SELECT in URI | UNION-based extraction | T1190 | 16 |
| 1000002 | Single quote probe | Error-based probing | T1190 | 44 |
| 1000003 | Blind boolean (SUBSTRING) | Boolean blind injection | T1190 | 18 |
| 1000004 | information_schema enum | Schema enumeration | T1213 | 2 |

The single-quote probe fires most often because the apostrophe is the common opening token across nearly every injection variant. These rules are lab-tuned for a training portal where any SQL keyword in a URI is suspicious. Production deployment would need tighter scoping (source and destination, `flow:established`) and narrower content matches on generic keywords such as SUBSTRING. The full ruleset, alert counts, and false-positive notes are in the `detection/` folder of this repository.

## 9. Confidentiality and authorization

This report documents a lab engagement against fictitious infrastructure (NexaCorp Industries, BeCode Brussels Mission 04). All indicators are lab-local artifacts. Publication for portfolio use was authorized by the BeCode lab coach (Thomas B.) on 2026-05-17.

---

*BeCode Corp, Incident Response Division. Confidential, do not distribute outside BeCode Corp.*
