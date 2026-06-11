# Detection engineering: Suricata SQLi ruleset

This folder contains the detection-engineering output for INC-2026-004. After the forensic investigation reconstructed the attack, the next defensive step was to write IDS signatures that catch each SQL injection technique the attacker used, then validate them against the captured traffic.

## Method

The capture was analysed offline, the deterministic and repeatable way to validate rules:

```bash
suricata -c /etc/suricata/suricata.yaml -S detection/local-sqli.rules -r attack.pcap -l suri-out
```

Offline mode (`-r`) reads the pcap directly, so there is no interface MTU constraint and no live replay. The `-S` flag loads only this ruleset, which keeps the alert counts clean. The host had no default ruleset installed, so the baseline was zero alerts and every hit below comes from these four rules.

Each rule inspects the normalized `http.uri` sticky buffer. Suricata decodes URL encoding before matching, so a payload sent as `UNION%20SELECT` on the wire is matched as `UNION SELECT` in the buffer. The `content` strings are therefore written in decoded form, not percent-encoded.

## Rules and validated alert counts

Counts were produced on a single clean run over the full 6577-packet capture.

| SID | msg | Technique | MITRE ATT&CK | Alerts |
|-----|-----|-----------|--------------|--------|
| 1000001 | LOCAL SQLi UNION SELECT in URI | UNION-based data extraction | T1190 Exploit Public-Facing Application | 16 |
| 1000002 | LOCAL SQLi single quote probe | Error-based probing (`id=1'`) | T1190 | 44 |
| 1000003 | LOCAL SQLi blind boolean | Boolean blind via SUBSTRING | T1190 | 18 |
| 1000004 | LOCAL SQLi information_schema enum | Schema enumeration | T1213 Data from Information Repositories | 2 |

The single-quote probe fires most often (44) because the apostrophe is the common opening token across nearly every injection variant the attacker sent, including the UNION and blind-boolean payloads. The UNION SELECT and SUBSTRING rules count the specific extraction and blind-enumeration requests. The information_schema rule fires only on the two explicit schema-enumeration requests (table names, then column names for the `users` table), which matches the investigation timeline.

## False-positive considerations

These rules are intentionally simple, suited to a training portal where any SQL keyword in a URI is suspicious. In production they would need tuning:

- `UNION SELECT` and `information_schema` are strong signals and rarely appear in legitimate URIs, so they are low false-positive risk on their own.
- `SUBSTRING` is a common SQL function name and could appear in legitimate application parameters or search strings. In production this rule should be narrowed, for example by pairing it with a preceding quote or a comparison operator, or scoping it to the vulnerable endpoint.
- `id=1'` is narrow by design. It catches the probe pattern seen here but a real deployment should generalize the quote-after-value pattern rather than hardcode `id=1`, or scope detection to the known vulnerable parameter.

A production deployment would also add `flow:established` and restrict source and destination to the protected asset, rather than `any any -> any any`, to cut noise.

## Reproducing

From the evidence bundle (not committed, see repository `.gitignore`):

```bash
suricata -c /etc/suricata/suricata.yaml -S detection/local-sqli.rules -r attack.pcap -l suri-out
for m in "UNION SELECT in URI" "single quote probe" "blind boolean" "information_schema enum"; do
  printf "%-28s : " "$m"; grep -c "$m" suri-out/fast.log
done
```
