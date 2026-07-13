# AutoGov — Usage Guide

*English · [Русская версия](USAGE.ru.md)*

From “running in 2 minutes” to a production deployment with TLS/mTLS and signed
artifacts.

---

## 1. Quick start (demo, ~2 min)

Requires Docker with the Compose plugin.

```bash
git clone https://github.com/oleg-vdv/AutoGov.git
cd AutoGov/deploy
docker compose up --build
```

This brings up:
- **controlplane** at `http://localhost:8443`;
- **shadow-n8n** — an intentionally unmanaged n8n instance (what the product
  should find);
- **agent** — a sensor that discovers the n8n instance within ~30 s.

Open `http://localhost:8443`, sign in with token **`dev-admin`**. You'll see the
instance inventory, risk-scored findings with explanations, the access map, and
report-export buttons. The UI has an **EN/RU** toggle in the top bar.

Dev tokens: `dev-admin` (admin), `dev-analyst` (analyst), `dev-viewer` (viewer).
The demo uses HTTP — local evaluation only.

---

## 2. Build from source

Requires Go 1.24+.

```bash
git clone https://github.com/oleg-vdv/AutoGov.git
cd AutoGov
make build   # → bin/agent, bin/controlplane, bin/autogov-sign
make test
```

### Control plane

```bash
cp deploy/controlplane.example.json /etc/autogov/controlplane.json
# edit tokens and notify targets
./bin/controlplane -config /etc/autogov/controlplane.json
```

### Agent (on each protected host)

```bash
cp deploy/agent.example.json /etc/autogov/agent.json
# set control_plane_url and token
./bin/agent -config /etc/autogov/agent.json          # daemon
./bin/agent -config /etc/autogov/agent.json -once     # single pass, for testing
```

---

## 3. Control plane configuration

`controlplane.json`:

| Field | Meaning |
|---|---|
| `listen` | listen address, e.g. `:8443` |
| `data_dir` | store location (snapshot + audit log) |
| `mode` | `onprem` (default; external egress denied) or `saas` |
| `allow_external_egress` | explicitly permit external destinations in on-prem (cross-border transfer!) |
| `tls.cert_file/key_file` | server TLS |
| `tls.client_ca_file` | CA for **agent mTLS** (if set, `/ingest` requires a client cert) |
| `agent_tokens` | bearer tokens for agents |
| `api_tokens` | map of `token → role` (`viewer`/`analyst`/`admin`) |
| `vuln_feed` | path to an offline vulnerability feed (JSON) |
| `notify` | notification channels (see §6) |
| `risk_weights` | (optional) override the scoring weights |

### Roles (RBAC)

| Role | Access |
|---|---|
| `viewer` | summary, instances, findings, hosts |
| `analyst` | + access map (sensitive), change finding status, autodoc |
| `admin` | + whitelisting, report export, audit log |

---

## 4. Agent configuration

`agent.json` — enable only the collectors you need (least privilege):

| Field | Meaning |
|---|---|
| `control_plane_url` | control plane address (https in prod) |
| `token` | agent token from `agent_tokens` |
| `interval_seconds` | full-scan cadence |
| `docker_socket` | socket path, or `"off"` to disable the Docker collector |
| `scan_roots` | extra directories to search for `~/.n8n`/compose/`.env` |
| `net_targets` | list of `host:port` to fingerprint |
| `n8n_api_base` / `n8n_api_key` | (optional) authorized workflow inventory via API (admin-provided key) |
| `tls.*` | client cert for mTLS, CA |
| `release.*` | artifact signature verification (see §7) |

> **The Docker socket is a root-equivalent.** Mount it **read-only**
> (`:/var/run/docker.sock:ro`). Without the socket the agent degrades (no
> containers) but keeps working via processes/filesystem/network — no root
> required.

---

## 5. Production: TLS and mTLS

```bash
# 1. Your own CA
openssl req -x509 -newkey ed25519 -days 3650 -nodes -keyout ca.key -out ca.crt -subj "/CN=AutoGov CA"
# 2. Control-plane server cert (CN/SAN = your hostname)
openssl req -newkey ed25519 -nodes -keyout server.key -out server.csr -subj "/CN=controlplane.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out server.crt
# 3. Agent client cert
openssl req -newkey ed25519 -nodes -keyout agent.key -out agent.csr -subj "/CN=agent-01"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out agent.crt
```

Control plane: `tls.cert_file/key_file` = server.\*, `tls.client_ca_file` = ca.crt.
Agent: `tls.client_cert_file/key_file` = agent.\*, `tls.ca_file` = ca.crt. Now
`/ingest` accepts only agents with a valid client certificate **and** token.

---

## 6. Notifications and SIEM

```json
"notify": {
  "min_severity": "medium",
  "syslog": [{ "network": "udp", "address": "10.0.0.10:514" }],
  "webhooks": [{ "url": "https://hooks.internal/autogov" }],
  "smtp": { "address": "mail.internal:25", "from": "autogov@corp", "to": ["soc@corp"] }
}
```

- **syslog/CEF** — findings ship to Wazuh/Splunk in CEF format.
- **On-prem egress guard:** in `mode: onprem`, external destinations (public IPs)
  are **rejected at startup** — protection against cross-border transfer. To
  allow (e.g. Telegram), set `allow_external_egress: true`.

---

## 7. Signed artifacts (agent integrity, spec §9)

```bash
# 1. Once: generate a release key (keep the private key offline!)
./bin/autogov-sign keygen -out-dir keys
# 2. Per release: sign the binaries
./bin/autogov-sign sign -key keys/release.key -version 0.1.0 -out manifest.json bin/agent bin/controlplane
# 3. Verify (the agent does the same at startup)
./bin/autogov-sign verify -pub keys/release.pub -manifest manifest.json -dir bin
```

Distribute `manifest.json` and the public key to hosts; in `agent.json`:

```json
"release": { "manifest_path": "/etc/autogov/manifest.json", "public_key": "<contents of release.pub>", "enforce": true }
```

With `enforce: true` the agent **refuses to start** if its binary is modified or
the signature is invalid (fail-closed).

---

## 8. Whitelisting (false-positive control)

Mark IT-sanctioned instances so the product doesn't cry wolf on CI/CD:

```bash
curl -H "Authorization: Bearer <admin>" -H "Content-Type: application/json" \
  -X POST https://cp/api/v1/whitelist \
  -d '{"kind":"image","pattern":"ci/*","reason":"sanctioned CI runners"}'
```

`kind`: `host` | `image` | `engine` | `instance` | `identity`; `pattern`
supports `*` and `?`. Rules re-score findings immediately.

---

## 9. Reports (admin)

```bash
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=json" -o report.json
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=csv"  -o findings.csv
curl -H "Authorization: Bearer <admin>" "https://cp/api/v1/reports/export?format=pdf"  -o report.pdf
```

JSON is the machine-readable source of truth; CSV is findings for spreadsheets;
PDF is a human summary for the CISO.

---

## 10. Verifying the acceptance criteria (spec §12)

On a test perimeter with intentionally deployed “shadow” instances:

1. Spin up several n8n instances (Docker, `npx n8n`, localhost-only, LAN) →
   all should appear in the inventory.
2. Check the “credentials → target systems” map and risk categories.
3. Capture the agent's traffic (`tcpdump`) — confirm **no secret value** is sent
   (only names and SHA-256 fingerprints).
4. Deploy `mode: onprem` — confirm no outbound connections to external services.
5. Confirm findings reach Wazuh (syslog/CEF) and a report exports.

---

## FAQ

**Does the agent need root?** No. Docker inspection needs read-only socket
access; the rest uses ordinary permissions. Without the socket, features
degrade rather than fail.

**Does the agent decrypt n8n credentials?** Never. Only the fact one exists, its
type, and the target system.

**Does it work air-gapped?** Yes: no external dependencies; PDF/signing/
explanations are generated locally; the vuln feed is an offline file.

**Windows hosts?** MVP is Linux-first. Windows agent is Stage 2.
