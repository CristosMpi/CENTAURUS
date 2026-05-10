# NEN CENTAURUS Security Map (ORIGIN)

## What makes this version more advanced
1. **Mission-aware scoring** (`critical_infra`, `enterprise_edge`, `remote_outpost`) so risk posture adapts to asset criticality.
2. **Threat-intel-assisted networking** with `threat_intel_reputation` and `lateral_movement_edges`.
3. **Kernel drift analytics** via `kernel_module_drift_score`.
4. **Deception engineering signals** (`honeytoken_touched`, `decoy_service_touched`, `canary_credential_used`) to identify active human adversaries.
5. **MITRE ATT&CK mapping** in every domain score for faster SOC triage and reporting.

## Domain Utility and Attack Prevention

### Identity Domain
Useful for account trust and operator integrity.
Prevents/detects: credential stuffing, stolen valid accounts, privilege misuse.

### Network Domain
Useful for perimeter and east-west movement analysis.
Prevents/detects: brute force, port-scan recon, C2 beaconing, exfiltration, lateral spread.

### Runtime Integrity Domain
Useful for host trust assurance.
Prevents/detects: firmware tampering, bootkits, process injection, kernel persistence.

### Physical + Deception Domain
Useful for protected edge nodes and unattended infrastructure.
Prevents/detects: tampering, covert proximity attacks, adversary interaction with honey assets.

### Fusion + Response Layer
Useful for correlated attack chains and operator actioning.
Outputs:
- Unified risk score + category
- Kill-chain stage inference
- Containment plan
- Immediate SOC action checklist
