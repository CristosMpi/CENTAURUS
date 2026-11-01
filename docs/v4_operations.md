# Deploy and operate CENTAURUS V4

## Production startup

Install the hash-locked runtime and create a new production identity. Example for a dedicated Linux account:

```bash
python -m pip install --require-hashes -r requirements-lock.txt
python -m scripts.abyssal provision \
  --directory /srv/centaurus/credentials \
  --node origin-node-17 --key-id origin-node-17-key-01 \
  --host centaurus.example.org
```

Provisioning creates `server.json` and `device.json` with mode 600 in a private directory. Transfer `device.json` through a secure administrative channel to the collector, then remove the server's copy after verifying delivery. The server needs only the public-key registry and its independent audit key in `server.json`. Securely back up the audit key; do not rotate it in place while retaining a chain made with the previous key. Configuration filenames, device private keys, and generated state are excluded from the supplied image and default credential directory is Git-ignored. Custom secret directories must also remain outside version control.

Install a valid certificate and private TLS key accessible only to the service account. Run:

```bash
export CENTAURUS_CONFIG_FILE=/srv/centaurus/credentials/server.json
python -m uvicorn app_v4.main:create_app --factory \
  --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /srv/centaurus/tls/key.pem \
  --ssl-certfile /srv/centaurus/tls/cert.pem \
  --no-proxy-headers --no-server-header \
  --limit-concurrency 64 --timeout-keep-alive 5 \
  --h11-max-incomplete-event-size 8192
```

Use a dedicated non-root account, a service supervisor with restart limits, and a persistent local disk. The state directory must be mode 700 and database mode 600 on POSIX. Do not place it on network filesystems or synchronize live SQLite files with a file-sharing tool. Multiple workers may share the same local database; separate replicas on different machines require an external atomic state implementation before deployment. The current implementation is a single-host service, not a distributed security plane.

Synchronize clocks, restrict ingress to expected collectors where practical, add upstream connection and header timeouts, and monitor 401/409/429/503 rates, disk capacity, and audit record count. `GET /health` is liveness only; it does not continuously validate all earlier audit entries or guarantee that the next write can succeed. Run `verify-audit` periodically under your existing operational monitoring.

If TLS terminates at a reverse proxy, prevent direct client access to the backend and trust forwarding headers only from the explicitly configured proxy address. Do not use `--forwarded-allow-ips '*'`. The supplied image uses direct TLS to avoid implicit proxy trust.

## Docker

Build with `docker build -t centaurus:4-abyssal .`. The image runs as UID/GID 10001 and starts only V4. Prepare persistent directories owned by that UID, with private permissions. Set the config's `state_path` to `/state/abyssal.sqlite3` and list the real hostname in `allowed_hosts`.

```bash
docker run --rm --name centaurus \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -p 8443:8443 \
  -e CENTAURUS_CONFIG_FILE=/run/centaurus/server.json \
  --mount type=bind,src=/srv/centaurus/credentials/server.json,dst=/run/centaurus/server.json,readonly \
  --mount type=bind,src=/srv/centaurus/tls,dst=/run/tls,readonly \
  --mount type=bind,src=/srv/centaurus/state,dst=/state \
  centaurus:4-abyssal
```

The command assumes the mounted TLS directory contains `key.pem` and `cert.pem`. Rebuild the image for base-image and dependency updates; hashes lock Python artifacts but do not freeze or certify the operating system image. Validate certificate renewal and restart procedures in staging.

## Add, rotate, or revoke a device

For each collector, generate a separate Ed25519 key pair with `provision --directory <new-private-directory> --node <node-id> --key-id <new-key-id>`. Copy only its `keys` registry entry into the active server configuration. Keep the existing server audit key and `state_path`. Copy the new `device.json` to the collector. All registry entries restrict a key to exactly one node.

For rotation, add the new key ID alongside the old one, restart all service workers, switch the collector, then set the old entry's `enabled` to `false` and restart all workers again. For urgent revocation, disable the compromised entry and restart all workers immediately. Configuration is loaded at startup, not hot-reloaded. Remove obsolete disabled entries after operational review to keep the registry bounded. Restore the registry and collector clocks carefully after disaster recovery.

## Audit verification and retention

Save each important `X-Audit-Sequence` and `X-Audit-Digest` receipt in a separate trusted system. A stopped or read-only verification window avoids the audit head advancing while comparing an exact saved head:

```bash
python -m scripts.abyssal verify-audit \
  --config /srv/centaurus/credentials/server.json \
  --expected-sequence 42 --expected-digest <independently-saved-digest>
```

Without expected values, the tool verifies the local chain only. An exact-head mismatch can also mean legitimate later records exist; investigate before declaring tampering. Never delete audit rows from a live database to free space. The default one-million-record cap fails closed before growth continues.

Before reaching capacity, stop ingestion, verify the chain, save its final receipt externally, and archive the complete database and audit key securely. Wait at least twice the configured signature clock-skew window before starting a new empty database, so captured signatures whose nonces existed only in the archive have expired. Start a new chain at a new private state path and record the previous chain's final receipt and the new chain's start in the external archive. This rotation is deliberate maintenance and is not automated by the service. Backups and receipt retention must meet your project's retention needs.

If an audit key or server host is compromised, preserve evidence and re-provision the service from a trusted environment. A valid local HMAC chain cannot establish integrity after its signing key is stolen. On corruption or disk failure, investigate and restore a verified backup; do not disable replay checks or audit commits to get the API running.

## Migrate from V3

1. Deploy V4 on an isolated staging listener using the factory entrypoint.
2. Provision device identities and adapt collectors to the versioned signature protocol.
3. Send current, timezone-aware event timestamps and explicit integrity evidence.
4. Update consumers for V4 fields: `recommended_actions`, `policy_triggers`, `evidence_gaps`, and audit receipt headers. Stop relying on V3's confidence and `prevented_attacks` fields.
5. Verify valid requests, rejection paths, TLS, revocation, persistent state, and restart behavior against the real deployment.
6. Move clients to `/v4/assess` and retire old listeners. Historical `app.main:app`, `app_v2.main:app`, and audio-model endpoints remain separate legacy applications and must not be exposed as an authentication bypass.

ORIGIN DUO can consume the response and retain receipts, but a deployed DUO integration is outside this repository. Containment is always advisory here; a separate, authenticated approval and execution workflow is required for real firewall or credential changes.
