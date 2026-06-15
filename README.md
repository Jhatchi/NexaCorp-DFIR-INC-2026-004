# NexaCorp DFIR Engagement (INC-2026-004) - SQL Injection Investigation

Forensic investigation of a SQL Injection attack against the NexaCorp employee self-service portal (`bru-web-01`). An external attacker abused the portal login and account-lookup form to read the back-end database, exfiltrated the full `users` table, cracked a weak credential offline, and reused it to obtain an authenticated SSH foothold on the same server. Conducted as a solo engagement during the BeCode Brussels Blue & Red Team bootcamp (Mission 04), as the continuation of [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001), [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002), and [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003). The series continues with [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005), an OS command injection and web shell investigation on the same `bru-web-01` portal.

![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004/actions/workflows/ci.yml/badge.svg)
![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)
![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)
![Web](https://img.shields.io/badge/class-OWASP%20A03%20Injection-orange.svg)
[![CWE](https://img.shields.io/badge/CWE--89-SQL%20Injection-orange.svg)](https://cwe.mitre.org/data/definitions/89.html)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

## Operational notice

**This is a lab engagement against fictitious infrastructure.** NexaCorp Industries is a fictional client used as the scenario for BeCode Brussels Mission 04. The host `bru-web-01` is an isolated lab VM running a deliberately vulnerable web application (DVWA). No real organization, network, or human was attacked.

All IP addresses, hostnames, account names, hashes, and indicators of compromise published in this report (`172.16.50.10`, `bru-web-01`, `j.martin`, `dvwa`, the MD5 hashes, etc.) are **lab-local artifacts**, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs.

**Publication authorized** by BeCode lab coach (Thomas B.) on 2026-05-17 for portfolio use of delivered BeCode missions. The full confidentiality statement appears in the findings report.

## At a glance

| Engagement metadata | Value |
| ------------------- | ----- |
| Reference | `BCC-2026 / INC-2026-004` |
| Deliverable | Findings Report (INC-2026-004) |
| Target | `bru-web-01`, NexaCorp employee self-service portal |
| Scope | Forensic analysis of the evidence bundle (Phase 1 to 4, investigation only) |
| Delivered | 2026-06-11 |
| Status | Complete and submitted |

| Investigation output | Value |
| -------------------- | ----- |
| Attack class | SQL Injection (OWASP A03), error-based then UNION-based |
| INC-2026-004 findings | **4** (2 CRITICAL, 2 HIGH) |
| Severity model | Analyst-rated (impact + technique category + threat state), no CVSS |
| Accounts exposed | 6 (full `users` table), 1 employee account compromised end to end |
| Evidence sources analyzed | web_access.log, attack.pcap, wazuh-alerts.json, auth.log |
| Cross-source corroboration | Apache access log (local +02:00) cross-checked against packet capture |

## Engagement context

**Scenario (fictional).** NexaCorp Industries reported a fourth security incident, this time on its web application layer. After three incidents on the Linux infrastructure (INC-2026-001 to 003), the same threat actor shifted to a new attack surface: the employee self-service portal `bru-web-01`. The web application firewall logged unusual query patterns (`syntax error`, `UNION SELECT`) against the login and account-lookup form, which talks directly to a back-end database.

**Mandate.** Marc Wauters (IT Infrastructure Manager) required a determination of whether the form was successfully abused, what data the attacker read, which employee accounts were exposed, and what the attacker did with what they stole.

**Scope.** Forensic analysis of the evidence bundle only. The investigation covers Phase 1 (web access log), Phase 2 (PCAP response analysis), Phase 3 (SIEM alerts), and Phase 4 (consequence analysis in auth.log). It also includes the Suricata detection-engineering phase: four IDS signatures written and validated against the capture, see the `detection/` folder. The attack window investigated is 2026-05-30, 09:35 to 14:48 (+02:00).

**Educational context.** Delivered during the **BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026)** as Mission 04. Investigation conducted on the BeCode SOC training workstation, accessed remotely via SSH over Tailscale VPN.

## Executive summary

An external attacker abused a vulnerable form on the NexaCorp employee portal to run SQL Injection against the back-end database. The attacker first confirmed the flaw with a simple error-based probe, then mapped the database and extracted the full `users` table, including every username and password hash. One of those accounts, the employee `j.martin`, used a password that was weak enough to be recovered offline in under a second.

About five hours after the data was stolen, the attacker reused the recovered password to log in over SSH to the same server, and the login succeeded. The attacker then tried the other stolen accounts over SSH, which failed. The result is a confirmed authenticated foothold on `bru-web-01` under a legitimate employee identity, and the exposure of every credential stored in the portal database.

The operation is deliberate and methodical: a textbook reconnaissance-to-exploitation sequence on the web layer, immediately followed by credential reuse against a second service. The most urgent element is the live SSH access, which is the entry point for follow-on activity. Immediate password rotation, account lockdown, and a code fix on the portal are required.

## Kill chain summary

The attack ran as a textbook reconnaissance-to-exploitation chain on the web layer, then pivoted to SSH:

1. **Probe**: an error-based single-quote test (`id=1'`) confirmed the SQL injection on the `id` parameter.
2. **Mapping**: column counting (`ORDER BY`) and a `UNION SELECT`, then enumeration of `information_schema` (table and column names).
3. **Exfiltration**: the full `users` table was dumped, including six accounts and their MD5 password hashes.
4. **Offline cracking**: the `j.martin` hash was recovered offline against a standard wordlist in under one second, on the analyst workstation, never against the live server.
5. **SSH pivot**: the recovered credential was reused over SSH to `bru-web-01` and the login succeeded, giving an authenticated foothold under a legitimate employee identity. The other stolen accounts, tried over SSH, failed.

## Findings summary

| ID | Severity | Title | Primary MITRE technique |
| --- | --- | --- | --- |
| **4.1** | 🔴 CRITICAL | SQL Injection on the `id` parameter (error-based then UNION) | T1190 |
| **4.2** | 🟠 HIGH | Database enumeration and full `users` table exfiltration | T1213 |
| **4.3** | 🟠 HIGH | Weak credential recovered offline (`[REDACTED-lab-credential]`, MD5) | T1110.002 |
| **4.4** | 🔴 CRITICAL | Credential reuse, successful SSH foothold as `j.martin` | T1078, T1021.004 |

**Severity distribution:** 2 CRITICAL / 2 HIGH

**Severity model.** Severities are analyst-rated, not CVSS-derived. Each rating is a contextual judgement based on operational impact on NexaCorp, the MITRE ATT&CK technique category, and the current threat state (the SSH foothold is live, not historical). Finding 4.4 is the most urgent: the attacker holds a valid interactive session under a real employee identity, which directly enables the next stage of the intrusion.

## How to read this repository

| If you are a... | Start here | Time |
| --------------- | ---------- | ---- |
| **Recruiter or hiring manager** | This README + the report executive summary | 5 min |
| **SOC analyst evaluating fit** | [`reports/INC-2026-004_Findings_Report.md`](reports/INC-2026-004_Findings_Report.md) findings section + [`evidence-summary/ioc-summary.md`](evidence-summary/ioc-summary.md) | 20 min |
| **DFIR practitioner** | Full report + [`methodology/attack-timeline.md`](methodology/attack-timeline.md) + [`notes/journal.md`](notes/journal.md) for the investigation trail | 40 min |
| **Anyone who wants to grep, cite, or diff** | [`reports/INC-2026-004_Findings_Report.md`](reports/INC-2026-004_Findings_Report.md) (Markdown source) | as needed |

**Canonical deliverable:** the PDF in [`reports/`](reports). The Markdown source is the same content, kept in the repo for searchability and version control.

## Methodology

The engagement follows the same industry-standard frameworks as the prior missions, applied to a web-layer investigation:

- **NIST SP 800-61r2** (Computer Security Incident Handling Guide): provides the Detection & Analysis structure. This investigation maps to the Detection & Analysis and Post-Incident Activity phases.
- **SANS PICERL**: the Identification stage is the core of the work (log correlation, request-response reconstruction). Containment, eradication, and recovery are documented as prioritised recommendations, not executed.
- **MITRE ATT&CK Enterprise v15**: every finding is mapped to one or more techniques. See [`methodology/attck-mapping.md`](methodology/attck-mapping.md).
- **OWASP**: the root vulnerability is classified under OWASP A03:2021 Injection. The full SQLi technique chain (error-based, column counting, UNION enumeration, blind boolean) is documented in the report.

### Evidence and timezone handling

The Apache access log (`web_access.log`) and the auth log are native local time (UTC+02:00, CEST). The packet capture window in `README.txt` is expressed in UTC. The access log is treated as the authoritative source for the exact request times, including the exfiltration moment. Where the capture window is referenced, the UTC value is noted alongside.

## Tools used

### Log analysis

- `grep`, `awk`, `sort`, `uniq` on `web_access.log`:
  - `awk '{print $1}' web_access.log | sort | uniq -c | sort -rn` to isolate the attacker IP (the only source outside the internal `192.168.10.0/24` range)
  - `grep` with a SQL-keyword pattern to extract the malicious requests in attack order

### Packet analysis

- `tshark` (CLI only):
  - `tshark -r attack.pcap -Y 'http.request and ip.src==172.16.50.10' -T fields -e tcp.stream -e http.request.uri` to map malicious requests to TCP streams
  - `tshark -r attack.pcap -q -z follow,tcp,ascii,N` to read the server responses (database name, dumped rows)

### Offline hash cracking

- `john` (Raw-MD5) against `rockyou.txt`, run on the analyst workstation only, never against the live server. The hash was recovered in under one second.

### Environment

- `bash` on the BeCode SOC training workstation, plus the analyst Mac for the offline crack. VS Code and Markdown for notes and report authoring.

## Detection engineering

After the forensic reconstruction, four Suricata signatures were written, one per SQL injection technique the attacker used, and validated offline against the 6577-packet capture (`suricata -r`, deterministic, zero-alert baseline). INC-2026-001 shipped a Suricata ruleset and INC-2026-002 shipped Wazuh rules; this incident continues that line on the web layer.

| SID | Technique | MITRE | Alerts |
|---|---|---|---|
| 1000001 | UNION SELECT in URI | T1190 | 16 |
| 1000002 | single-quote probe (`id=1'`) | T1190 | 44 |
| 1000003 | blind boolean (SUBSTRING) | T1190 | 18 |
| 1000004 | information_schema enumeration | T1213 | 2 |

Each rule inspects the normalized `http.uri` sticky buffer (Suricata decodes URL encoding before matching). The rules are intentionally simple for a training portal; production tuning (scoped source and destination, `flow:established`, narrower matches on generic keywords like SUBSTRING) is documented in [`detection/README.md`](detection/README.md), with the per-rule alert counts, MITRE mapping, and false-positive notes.

## Repository layout

```text
NexaCorp-DFIR-INC-2026-004/
├── README.md                                  (this file)
├── LICENSE                                    (MIT)
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml                             markdownlint + typography validation
├── reports/
│   ├── INC-2026-004_Findings_Report.pdf        canonical deliverable (generated separately)
│   └── INC-2026-004_Findings_Report.md         same content, Markdown source
├── methodology/
│   ├── attack-timeline.md                     minute-by-minute attack timeline
│   └── attck-mapping.md                        ATT&CK matrix for this incident
├── evidence-summary/
│   └── ioc-summary.md                         IOCs in SIEM-ingestible format
├── detection/
│   ├── local-sqli.rules                       four validated Suricata SQLi signatures
│   └── README.md                              rules, alert counts, MITRE, FP notes
└── notes/
    └── journal.md                             analyst investigation notebook
```

## Reproducibility

The evidence bundle is BeCode lab property and is not redistributed. Every claim in the report is traceable to a specific log source, packet stream, and timestamp, so anyone with their own copy of the bundle can reproduce the analysis.

### Reproduce key findings

Requires the evidence bundle (`logs/web_access.log`, `logs/auth.log`, `attack.pcap`):

```bash
# Finding 4.1: isolate the attacker (only IP outside 192.168.10.0/24)
awk '{print $1}' logs/web_access.log | sort | uniq -c | sort -rn

# Finding 4.1: the SQLi technique chain, in order
grep "172.16.50.10" logs/web_access.log | grep -iE "union|select|order|%27|information_schema"

# Finding 4.2: read the server response containing the dumped users table
tshark -r attack.pcap -Y 'http.request and ip.src==172.16.50.10' \
  -T fields -e tcp.stream -e http.request.uri | grep -iE "FROM%20users"
tshark -r attack.pcap -q -z follow,tcp,ascii,447 | grep -iE "First name|Surname|[a-f0-9]{32}"

# Finding 4.2: read the enumerated database name
tshark -r attack.pcap -q -z follow,tcp,ascii,14 | grep -iE "Surname|First name"

# Finding 4.3: crack the j.martin hash offline (analyst workstation)
echo '[REDACTED-md5]' > jmartin.hash
john --format=raw-md5 --wordlist=/path/to/rockyou.txt jmartin.hash
john --show --format=raw-md5 jmartin.hash

# Finding 4.4: credential reuse over SSH
grep -iE "172.16.50.10|j.martin" logs/auth.log
```

## Known limits

- **Forensic-only scope.** This is an investigation lab. Severities are analyst-rated (impact, technique category, threat state), not CVSS-derived.
- **Detection rules are lab-tuned (v2 pending).** The four Suricata signatures in `detection/` are intentionally simple, suited to a training portal. Production deployment would need tuning (tighter source and destination scoping, `flow:established`, narrower content matches on generic keywords like SUBSTRING), and adding equivalent Wazuh detection logic. This is documented in `detection/README.md`.
- **Evidence bundle not redistributed.** The bundle is BeCode lab property. Claims are reproducible by anyone holding their own copy, but the raw logs and packet capture are not published here.
- **Server-side query not recovered.** The exact back-end SQL statement is inferred from the injection behaviour and the responses, not read from application source code.
- **Post-foothold activity undetermined.** The successful SSH session as `j.martin` is confirmed, but what the attacker did inside that session is not reconstructible from this bundle. It is the starting point for the next incident.
- **Capture window.** The PCAP covers the attack window, not the surrounding day. There is no memory acquisition and no filesystem image.

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- **INC-2026-004**: this repository
- [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005): OS command injection and web shell (web portal)
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (web portal)

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design, evidence bundle preparation, publication authorization for portfolio use (2026-05-17).
- **MITRE** for the ATT&CK knowledge base used to map every finding.
- **OWASP** for the injection taxonomy used to classify the root vulnerability.

## About

Solo DFIR investigation delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 04, submitted 2026-06-11.

Author: **Johan-Emmanuel Hatchi**, French national based in Brussels, cybersecurity student at BeCode Brussels (Nov 2025 to Sep 2026), active internship search for September 2026.

[GitHub](https://github.com/Jhatchi) - [LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC L1/L2, DFIR junior, or detection engineering roles where this kind of end-to-end work (web log analysis, packet inspection, offline credential cracking, cross-source correlation, formal client reporting) is in scope.

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The report text and the methodology notes are released under MIT: free to copy, adapt, and reuse with attribution. The evidence bundle, lab infrastructure, and original engagement briefings remain BeCode Brussels property and are not redistributed.
