# Implementation contract — 0.1.0

Historical contract. Authentication requirements are superseded for 0.5.0 by [KUBECONFIG-ONLY-CONTRACT](docs/KUBECONFIG-ONLY-CONTRACT.md): no runtime OIDC. The earlier 0.4 contract describes an intermediate version. Isolation, ownership, TLS/egress and scope restrictions remain; see current [kubeconfig guidance](docs/KUBECONFIG-AUTH.md).

This is a separate local project. Do not touch power-motors or adjacent projects. No real cluster/IdP access, production mutation, external publishing, or web research. Frontend, backend and security implementations share this contract. All network integrations must fail closed. Python 3.12+, FastAPI, SQLAlchemy, PostgreSQL production; SQLite only in tests. React+TypeScript. UTC ISO-8601 timestamps. No invented scan results or percentages.

## Python modules (`src/workbench/`)

`domain.py` (main owns):
- `DomainError(message: str, code: str = 'invalid_input')`; sanitized messages only.
- `ScanResult` dataclass: `findings: list[dict]`, `coverage: list[dict]`, `versions: dict`, `limitations: list[str]`.
- Finding dict fields: rule_id, title, severity (critical/high/medium/low/info/unknown), namespace, resource_kind, resource_name, resource_uid, category, scanner, evidence (dict), recommendation, confidence (high/medium/low), image_digest?, package?, vulnerability_id?, location?. No secrets. User-visible text always escaped.
- Coverage dict fields: check, status (completed/denied/error/not_checked/unsupported), detail.

### Security owner — security.py, oidc.py, tests/test_security.py, tests/test_oidc.py

- `Vault(key: str)` expects base64url 32 byte key; `encrypt(value: dict, purpose: str) -> str`, `decrypt(ciphertext: str, purpose: str) -> dict`. Authenticated encryption with purpose binding. No fallback key.
- `inspect_kubeconfig(text: str) -> list[dict]`: strict bounded YAML, reject aliases/duplicate keys/complexity/unsafe tags/external paths/proxy/insecure TLS; NEVER execute exec or auth-provider. Entries: context, cluster_name, server, ca_data (base64 or None), username, auth_type, warnings. No tokens/keys from import returned. exec/auth-provider described as unsupported instructions ignored; extract metadata only. No full input logged.
- `validate_endpoint(url: str, allowed_cidrs: list[str], allowed_hosts: list[str]) -> list[str]`: HTTPS, no credentials/query/fragment, validate host AND all DNS addresses, deny loopback/link-local/metadata/multicast/unspecified even if broadly allowlisted; private CIDRs explicit. Return approved resolved IPs.
- `PinnedHTTP(allowed_cidrs: list[str], allowed_hosts: list[str], ca_data: str | None = None)` with `get_json(url, headers=None) -> dict`, `post_form(url, data: dict, headers=None) -> dict`, `post_json(url, data: dict, headers=None) -> dict`. Pin validated DNS addresses while preserving host/SNI, no redirect, no env proxy, max 8MiB, short timeouts. No exceptions expose tokens/responses.
- `password_hash(password: str) -> str`, `password_verify(password: str, encoded: str) -> bool` (stdlib scrypt acceptable).
- `OIDCProvider(config: dict, http: PinnedHTTP)` using administrator-supplied issuer, client_id, optional client_secret, redirect_uri, audience; exact issuer/discovery endpoints must be HTTPS and policy permitted.
- `begin() -> dict` keys state, nonce, verifier, authorization_url (code+PKCE S256, state nonce).
- `exchange(code: str, transaction: dict) -> dict`: validates signed ID token issuer/audience/exp/nonce/azp, allowed asymmetric algorithms only, bounded JWK parse; returns id_token, expires_at (UTC ISO), subject, refresh_token optional. No automatic refresh in this version. URL client_secret never used.
- `provider_metadata(config: dict) -> dict` sanitized id/display_name/issuer/client_id/audience only if useful.

### Scanner owner — scanners.py, tests/test_scanners.py

- `parse_report(scanner: str, data: dict) -> ScanResult` supports trivy JSON image report, kube-bench JSON and Kubescape JSON only known schemas; unknown/malformed is error not empty success. Bound output, redact sensitive content.
- `scan_inventory(connection: dict, scope: dict, http: PinnedHTTP, cancelled: Callable[[], bool]) -> ScanResult`. connection = server, ca_data, id_token; scope = namespaces (nonempty explicit list), max_objects (default 1000), timeout_seconds (max 600). Read-only GET lists namespaced deployments/statefulsets/daemonsets/pods, services, networkpolicies, roles/rolebindings, serviceaccounts as supported; do NOT read Secrets/configmaps/pod logs/exec/create. Report insufficient access per resource. Known deterministic workload checks e.g. privileged, host namespaces, root config. Findings preserve evidence with relevant security fields only, not arbitrary workload strings/env/secrets. Limited built-in checks must not pretend Kubescape. Cancellation raises DomainError(code='cancelled'). Pagination/caps mark incomplete, never silently truncate.
- `preflight(connection: dict, scope: dict, http: PinnedHTTP) -> list[dict]`: GET only resource permission probe (`?limit=1`), no SelfSubjectAccessReview POST; reports all required per namespace, no wildcards; no cluster discovery auto traversal.
- Need safe argument-vector subprocess adapter helper for future pinned CLI runtime optional; DO NOT download scanners or run external clusters. First delivery may import scanner reports and explicitly mark live CLI adapters unavailable pending verification. Document this honestly.

## API (`/api`, main owns)

Cookie sessions HttpOnly/SameSite strict, CSRF header `X-CSRF-Token` on POST/PATCH/DELETE except login. Cookies same origin, never tokens localStorage. Login {username,password}; response {user:{id,username,role}, csrf_token}. GET `/session` same shape, 401 logged out; POST `/logout`. Roles administrator/auditor/viewer/security_lead, backend checks + cluster grants (admin all). No default credentials: offline bootstrap CLI.

GET `/capabilities` returns {version, features:[{id,title,status,detail}], oidc_providers:[{id,display_name,issuer}], limits:{...}}; can be unauthenticated only version/features (no sensitive data), simplest require session.
GET `/overview` {clusters,runs,findings,coverage_gaps,workers:[...]} numeric counters; empty true empty state.
GET `/clusters` -> array {id,name,environment,context,server,status,created_at,credential_expires_at?,auth_type:'oidc',namespaces:[str],oidc_provider_id}.
POST `/kubeconfig/inspect` {content} -> {contexts:[{context,cluster_name,server,username,auth_type,warnings}]} (no ca_data to UI needed).
POST `/clusters` {name,environment,kubeconfig,context,namespaces:[str],oidc_provider_id} (administrator) -> cluster metadata; re-inspect server-side; original file/tokens never stored. If no configured provider returns configuration_required.
POST `/clusters/{id}/authorize` -> {authorization_url}; opens browser redirect. POST secured CSRF. GET `/oidc/callback?code=&state=` one-time same session state then 303 to frontend `/`; no tokens in URL or HTML. State expiry 5min; PKCE verifier encrypted server-side; single-use before exchange.
POST `/clusters/{id}/preflight` {namespaces:[str]} -> {coverage:[...]}.
DELETE `/clusters/{id}/credential` revoke stored material, cancel queued/active jobs; not claim JWT revocation at IdP.
POST `/runs` {cluster_id,namespaces:[str],timeout_seconds:300} -> run (auditor+). Refuse if no valid cluster credential. GET `/runs` -> array; GET `/runs/{id}` -> run with coverage, limitations, findings, versions. Run {id,cluster_id,cluster_name,status,stage,created_at,started_at,finished_at,error,cancel_requested,coverage,limitations,versions}. status queued/running/completed/partial/failed/cancelled/interrupted, no synthetic percentage. POST `/runs/{id}/cancel` -> run.
POST `/imports` {cluster_id,scanner:'trivy'|'kube-bench'|'kubescape',report:object} -> run with normalized findings; import never verifies cluster provenance; reports tagged imported and source confidence. GET `/findings?cluster_id=&severity=&q=` -> list findings with run_id,cluster_id,cluster_name,first_seen,last_seen,disposition:'open'|'confirmed'|'accepted_risk'|'false_positive',internal_priority? and normalized fields. PATCH `/findings/{id}` {disposition}; risk/false_positive require security_lead/admin; auditor confirms only. Finding observation not equal remediation status. No auto-close on absence in this version.
GET `/runs/{id}/report?format=json|markdown|html` attachment with scope/times/coverage/versions/evidence/limitations, authenticated permission check, audit event. Administrator/auditor/security_lead only export by default (viewer no export).
GET `/audit` -> array {id,created_at,actor,action,target,detail} administrator only, never credentials.
GET `/health/live` unauthenticated, GET `/health/ready` DB check no error traces; no arbitrary DB initialization in HTTP startup. Schema bootstrap explicit CLI.

Errors {detail: {code,message}}. FastAPI validation errors may be array; UI support both. All input body sizes <= 1 MiB default. UUID identifiers random. Cluster grants enforced for every item, run, finding, export. Denied object lookup returns 404.

## Frontend owner — only `frontend/**`

Create React/TypeScript Vite app, install deps with bun project-local, lockfile. No terminal or mock dashboard. UI Russian default, design tokens #e85002/#151515/#f8f8f8, dark #121212/#1b1b1c/#ff7d3d. Use system font fallback unless legally vendored font available. State-based navigation no router required. Login, Overview, clusters connection modal/wizard, runs/details, findings/detail/filter, imports, modes card/capabilities, admin audit. Static future screens explicitly not implemented. Never use dangerouslySetInnerHTML; safe text/evidence. Request wrapper gets CSRF from session/login response in memory only. All authenticated API endpoints protected, show errors/empty states/permission limitations. Build + TS tests. Bundle same origin via backend StaticFiles from WEB_DIST_DIR (default frontend/dist); Vite dev proxy /api -> 127.0.0.1:8080.

## Other owners

Main owns DB/API/worker/bootstrap/pyproject/dependencies/Compose/docs/README and integration. Do not edit another owner's files. Notify main on interface changes. Tests must be self-contained no network/real credentials. Do not claim live Keycloak/Dex or scanner compatibility tested. No commit/push requested.
