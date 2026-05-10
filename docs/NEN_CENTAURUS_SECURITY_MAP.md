# NEN CENTAURUS Security Map (ORIGIN)

This document maps each major module in NEN CENTAURUS to practical use-cases and attack prevention outcomes.

## 1) Identity Domain (`identity` in request)
**Useful for:** preventing stolen-account abuse in operator workflows.

**Signals:**
- `mfa_verified`
- `impossible_travel_flag`
- `privilege_escalation_attempts`

**Attacks prevented/detected:**
- Credential stuffing and password spraying
- Session hijacking from impossible geography changes
- Insider privilege abuse and role escalation abuse

## 2) Network Domain (`network` in request)
**Useful for:** detecting perimeter compromise and outbound attacker control.

**Signals:**
- `failed_logins_5m`
- `unique_ports_scanned_5m`
- `c2_beacon_score`
- `tls_fingerprint_mismatch`
- `egress_bytes_5m`

**Attacks prevented/detected:**
- Brute-force authentication campaigns
- Reconnaissance and exploit staging via port scans
- Malware command-and-control beaconing
- Data exfiltration
- Evasion through custom TLS tooling

## 3) Runtime Integrity Domain (`runtime` in request)
**Useful for:** trust validation of endpoint/edge compute layer.

**Signals:**
- `secure_boot_ok`
- `firmware_hash_match`
- `memory_tamper_alert`
- `unsigned_processes`
- `suspicious_syscalls_1m`

**Attacks prevented/detected:**
- Firmware tampering and bootkits
- In-memory code injection
- Unauthorized process execution
- Kernel/userland exploit behavior

## 4) Physical Domain (`physical` in request)
**Useful for:** protecting unattended field hardware and edge nodes.

**Signals:**
- `enclosure_opened`
- `vibration`
- `thermal_delta_c`
- `ultrasonic_motion_score`

**Attacks prevented/detected:**
- Physical tampering and forced entry
- Covert proximity intrusion
- Thermal sabotage patterns

## 5) Fusion + Response Layer (`assess_threat`)
**Useful for:** combining all domains into one actionable containment plan.

**Outcomes:**
- Calculates unified `risk_score` and `overall_risk`
- Maps event to likely kill-chain stage
- Produces containment actions for SOC/ORIGIN operators

**High-value prevention effect:**
Correlated network + runtime anomalies increase risk, making multi-stage attacker operations (e.g., foothold + persistence + exfiltration) harder to complete undetected.
