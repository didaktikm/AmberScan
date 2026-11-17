# Kubeconfig authentication implementation contract — 0.4.0

Historical: superseded for 0.5.0 by [KUBECONFIG-ONLY-CONTRACT.md](KUBECONFIG-ONLY-CONTRACT.md). OIDC is no longer an alternative in the current runtime. Frozen 0.4 schema/migrations retain this historical shape for upgrade/restore.

Approved extension supersedes OIDC-only requirements of earlier contracts; all isolation/security constraints remain. Work in this repository only; do not read `.local`/personal kubeconfigs, contact real Kubernetes/IdP, restart running deployment, publish, commit or push. Tests local mocked/disposable only. Owner boundaries below avoid concurrent edits.

## Interfaces

- Cluster adds `auth_type` string `oidc|kubeconfig` default/server_default oidc. `oidc_provider_id` nullable: required for OIDC, absent for kubeconfig. Old rows oidc. Credential and run schema fields reused; normalized encrypted auth below. New schema0.4.0/revision0004_kubeconfig_auth; preserve frozen older schemas. Invalidate old credentials/flows/run snapshots on explicit offline migration; preserve scopes/history. Explicit version→revision mapping.
- DraftInput extends with `auth_type` default oidc and `storage_mode` default run_only. kubeconfig auth requires connection.kind=kubeconfig and null/absent provider; oidc requires provider. Public Cluster auth_type oidc|kubeconfig, provider nullable; optional `credential_kind: token|client_certificate|oidc|null` if helpful.
- `POST /api/clusters/{id}/credential` {content,context,storage_mode:'run_only'|'persistent',expected_access_revision:int} -> Cluster view. Own draft or permitted ready, personal identity only. Match immutable endpoint/CA/context, invalidate old personal generation/jobs, atomically store replacement. No cluster configuration or scope mutation.
- `extract_kubeconfig_credentials(content,context) -> dict` (security.py): `{metadata: <same selected inspect record>, auth: <normalized auth>, source_expires_at: datetime|None}`. Public inspection NEVER returns auth. Parsing still bounded/all-document validation. Only inline token or cert/key, reject unsupported selected method. Source expiry for cert, optional restrictive JWT hint not treated as verification.
- Normalized auth: `{version:1,kind:'token',token:str}` or `{version:1,kind:'client_certificate',certificate_pem:str,private_key_pem:str}`. OIDC may retain legacy encrypted `{id_token}` but `credential_for` emits normalized auth. Connection shape `{server,ca_data,auth_type,auth,expires_at, ...AUTH_FIELDS}` (run additionally scope). Keep legacy id_token fallback in common helpers solely for OIDC existing tests/old internal callers; no generic bypass of malformed supplied auth.
- `connection_headers(connection) -> dict` in security.py validates normalized auth (or explicit legacy id_token fallback), returns Accept + Bearer for token, Accept-only for certificate. `connection_tls(connection) -> dict|None` returns normalized client certificate auth or None. Certificate PEM/key must not appear in errors/logs.
- `PinnedHTTP(..., ca_data=None, *, client_identity=None)`: optional normalized cert auth loaded into verified SSLContext via protected temporary files then immediately deleted, finally cleanup. Preserve DNS pinning and hostname/SNI. `PolicyHTTP(...,client_identity=None)` / `policy_http(session,settings,purpose,ca_data=None,*,client_identity=None)` forward only for Kubernetes; reject identity for OIDC. Call optional kwarg only when non-None to preserve existing test factories.
- App leases: run_only at most1h AND web session expiry; explicit persistent at most24h; cap cert/source expiry. Store only current user's normalized auth in Vault, never raw YAML. No refresh. run_only consumed on enqueue, not preflight/discovery.
- Providerless auth uses provider_revision=0 ONLY for kubeconfig; OIDC requires enabled provider/revision>0. Keep canonical policy→[provider]→cluster→binding locks, generation/session/grant fences. auth_type participates in fingerprints/snapshot checks.
- Discovery POST body `{continuation?:string}` default `{}`. Result existing fields plus `continuation: string|null`. Bounded batches <=1000/5 pages/30s; allow next batch via opaque encrypted purpose-bound cursor with user/session/cluster/exact credential/revisions/snapshot+expiry. No arbitrary URL; raw Kubernetes cursor not exposed as trusted authorization. Preserve sorted visible results, explicit incomplete state, snapshot-expired refresh, system names, selection limit100. UI append batches, never auto-select.
- `/capabilities` adds optional `kubernetes_setup_required` and `oidc_setup_required`; legacy setup_required describes Kubernetes policy missing, not provider absence. Missing Kubernetes-purpose rules must be distinguishable even if OIDC rules exist.

## File ownership

- security agent: security.py, scanners.py, configuration.py transport section only (PolicyHTTP/policy_http), new security/scanner tests. Coordinate before other configuration.py edits.
- schema agent: db.py, migrations.py, backup.py, admin.py, alembic/**, pyproject.toml/version __init__/uv.lock, schema/backup/admin tests and disposable smoke. Keep frontend and Compose version updates for main/frontend.
- backend agent: api.py, services.py, connections.py, namespaces.py, new API/discovery tests and related existing tests. No worker/security/db/migration edits.
- frontend agent: frontend/** only.
- main: worker.py/worker tests, docs/Compose/integration/review. No uncoordinated edits to another owner's files.

Verification: PYTHONPATH=src uv run --frozen pytest tests -q; bun run --cwd frontend test/typecheck/build. No real-cluster acceptance claim. Existing runtime0.3 remains unchanged until separately approved offline backup/upgrade/restart.
