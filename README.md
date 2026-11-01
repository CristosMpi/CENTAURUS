# CENTAURUS V4 — ABYSSAL

**Authenticated telemetry. Persistent replay defense. Conservative threat decisions.**

ABYSSAL is the hardened fourth version of ORIGIN's defensive decision engine. It combines identity, network, runtime integrity, physical tamper, and deception signals into an explainable assessment. It runs locally without an external AI service or cloud account.

Every assessment requires a provisioned device's Ed25519 signature. The server holds public device keys only. Production requires HTTPS, explicit allowed hosts, private configuration, and working security state. There are no default credentials or anonymous assessment routes.

## What changed

| Control | V4 behavior |
| --- | --- |
| Device identity | A key is restricted to one node; keys can be disabled or rotated |
| Request integrity | Exact body bytes, method, route, key ID, timestamp, and nonce are signed |
| Replay defense | Atomic SQLite nonce reservation, shared across workers and preserved across restarts |
| Input boundary | Strict types, finite bounded numbers, duplicate-field rejection, body/header limits, receive deadline |
| Resource controls | Persistent global and authenticated-device quotas; bounded nonce and audit capacity |
| Decision policy | Serious integrity failures have minimum risk levels; missing integrity remains unknown |
| Audit evidence | HMAC-linked records and receipts bind request and response digests to the decision |
| Containment | Recommendations require operator approval; no isolation or credential changes execute automatically |

This is a deterministic policy engine. A signed device can still report false observations if compromised. Its scores are policy scores, not calibrated probabilities. No remote attestation, hardware secure boot, firewall enforcement, or DUO integration is claimed by this API.

## Local quick start

Python 3.12 is the tested runtime. From the repository root, in a POSIX shell:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-lock.txt
python -m scripts.abyssal provision --development
export CENTAURUS_CONFIG_FILE="$PWD/.abyssal/server.json"
python -m uvicorn app_v4.main:create_app --factory \
  --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header \
  --limit-concurrency 64 --timeout-keep-alive 5 --h11-max-incomplete-event-size 8192
```

In another activated terminal, generate fresh **synthetic** telemetry and submit it:

```bash
python -m scripts.abyssal sample
python -m scripts.abyssal assess \
  --url http://127.0.0.1:8000/v4/assess --allow-local-http
python -m scripts.abyssal verify-audit
```

The toolkit creates private files and refuses to overwrite existing identities or samples. Generate a new sample filename with `--output` and pass it with `--payload` when the previous sample becomes stale. Device clocks must be synchronized. Development HTTP is an explicit local-only setup; follow the production guide before using real telemetry.

## API

| Route | Access |
| --- | --- |
| `POST /v4/assess` | Signed device request, fresh telemetry, matching node identity |
| `GET /health` | Minimal public liveness response |
| `GET /` | Public edition and endpoint metadata |

Successful assessments include domain explanations, policy triggers, evidence gaps, and approval-required recommendations. `X-Request-ID`, `X-Audit-Sequence`, and `X-Audit-Digest` provide correlation and an audit receipt. Full protocol and error semantics: [V4 security design](docs/v4_security.md).

## Production and migration

Use the new factory entrypoint, `app_v4.main:create_app --factory`. V1/V2/V3 routes and interactive docs are **not mounted** by V4. Historical applications remain in the repository for migration and regression tests; do not expose their old entrypoints alongside ABYSSAL.

Provision production credentials without `--development`, install valid TLS certificates, and deploy with private persistent state. See [deployment, key rotation, and recovery](docs/v4_operations.md). A non-root TLS Docker image is included; it needs operator-provided certificates and configuration.

## Validation

```bash
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install -r requirements-dev.txt
ruff check app_v4 scripts/abyssal.py tests/test_v4_api.py tests/test_v4_toolkit.py
ruff format --check app_v4 scripts/abyssal.py tests/test_v4_api.py tests/test_v4_toolkit.py
pytest -q
pip-audit --strict --disable-pip --no-deps -r requirements-lock.txt
```

CI runs security regressions, historical API tests, formatting, and the runtime advisory audit. Dependency and GitHub Actions updates are checked weekly. An advisory scan finds known published vulnerabilities; it is not a penetration test or a security certification.
