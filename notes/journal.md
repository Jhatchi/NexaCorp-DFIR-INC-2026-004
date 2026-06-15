# Analyst Journal - INC-2026-004

Reference: BCC-2026 / INC-2026-004. Analyst: Johan-Emmanuel Hatchi (blue11).

Informal investigation notebook, kept for the trail of reasoning. The polished version is the findings report.

## Working hypotheses

- **H1:** A single external source is responsible. Confirmed. One IP (`172.16.50.10`) sits outside the internal `192.168.10.0/24` range and carries every SQL keyword. The other five sources are internal staff loading the portal normally.
- **H2:** The injection succeeded (not just attempted). Confirmed. The PCAP responses contain the database name and the dumped table, so the server actually returned the stolen data.
- **H3:** At least one stolen credential is weak. Confirmed. `j.martin` cracked in under a second.
- **H4:** The attacker reused the credential elsewhere. Confirmed. Successful SSH login in `auth.log`.

## Step log

1. Counted requests per source IP. The attacker stood out instantly: 120 requests from `172.16.50.10`, all the others internal. Answered "who is the attacker".
2. Filtered the attacker's requests for SQL keywords. The endpoint and the vulnerable parameter (`id`) were obvious, and the whole technique chain was readable in order, like a story: probe, count columns, UNION, enumerate, dump, blind.
3. Switched to the PCAP for the server side. Mapped the interesting requests to TCP streams, then followed stream 14 (database name `dvwa`) and stream 447 (the full user dump). The access log shows requests, the PCAP shows responses. That distinction was the key mental model for this lab.
4. Picked the right account out of the dump. Six accounts came back, five of them DVWA defaults (admin, gordonb, 1337, pablo, smithy). `j.martin` is the only real-employee pattern and the only one the attacker re-queried by name. That is the account of concern.
5. Cracked the hash offline. The lab workstation had no john, no hashcat, no rockyou, and no internet (apt failed on DNS). Moved the crack to the analyst Mac: downloaded rockyou from the public source, ran john raw-md5, got `[REDACTED-lab-credential]` in under a second. Cracking stays off the live server by design.
6. Closed the loop in `auth.log`. Found the successful SSH login for `j.martin` from the attacker IP at 14:48:06, then the failed sprays of the other accounts. End to end chain confirmed.

## Lessons and snags

- **Bundle path differed from the briefing.** The archive extracted to `evidence_fixed/`, not `nexacorp-INC2026004-evidence/`. A `find . -maxdepth 2` sorted it out. Always confirm the real path before trusting the briefing's example commands.
- **Tooling absence is a signal, not a failure.** When john, hashcat, and rockyou were all missing on the workstation, the right move was to relocate the crack to an equipped machine, not to force an install that the isolated network could not support.
- **Complexity is not strength.** `[REDACTED-lab-credential]` passes every complexity checkbox and still falls instantly. Best single talking point from this lab.
- **Timezone discipline.** Access log and auth log are +02:00; the capture window in the README is UTC. The exfiltration time for any report question comes from the access log (09:39:58 +02:00), the authoritative source.
