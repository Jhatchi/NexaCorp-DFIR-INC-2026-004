# MITRE ATT&CK Mapping: INC-2026-004

Reference: BCC-2026 / INC-2026-004. Framework: MITRE ATT&CK Enterprise v15.

Every finding in the report is mapped to one or more techniques. This matrix is the standalone view.

## Technique matrix

| Tactic | Technique | ID | Finding | Evidence |
| ------ | --------- | -- | ------- | -------- |
| Initial Access | Exploit Public-Facing Application | T1190 | 4.1 | SQL Injection on the `id` parameter of the portal form |
| Collection | Data from Information Repositories | T1213 | 4.2 | Full `users` table dumped via UNION SELECT, read from the PCAP response |
| Credential Access | Brute Force: Password Cracking | T1110.002 | 4.3 | MD5 hash of `j.martin` cracked offline against rockyou |
| Defense Evasion / Persistence | Valid Accounts | T1078 | 4.4 | Reuse of a legitimate employee credential to authenticate |
| Lateral Movement | Remote Services: SSH | T1021.004 | 4.4 | Successful SSH login as `j.martin` from the attacker IP |

## Notes on mapping choices

- **T1190 over a generic injection label.** The portal is internet-facing from the attacker's position (external source IP), and the injection is the initial access vector, so T1190 is the correct tactic-level anchor rather than a generic application-abuse note.
- **T1213 for the table dump.** The `users` table is an information repository inside the application database. The dump is a Collection action, distinct from the exploitation that enabled it (4.1).
- **T1110.002 happens off-host.** Password cracking leaves no server log. It is mapped from the artifact (the weak hash) and the subsequent successful reuse, which proves the crack happened.
- **T1078 plus T1021.004 for the foothold.** The SSH login uses a valid account (T1078) over a remote service (T1021.004). Both apply to finding 4.4.

## Sequence view

```text
T1190 (exploit web form)
  -> T1213 (dump users table)
    -> T1110.002 (crack j.martin hash offline)
      -> T1078 + T1021.004 (reuse credential, SSH foothold)
```

This is a clean exploitation-to-foothold chain on a single host, where each technique enables the next.
