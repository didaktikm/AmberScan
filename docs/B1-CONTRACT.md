# B1 implementation contract (approved 2026-11-16)

Historical B1 contract. For0.4 personal kubeconfig authentication without OIDC see [KUBECONFIG-CONTRACT](KUBECONFIG-CONTRACT.md); personal credentials, revocation, TLS/egress, immutable leases and isolation remain required.

Working project only `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench`. Do NOT read `.local`, real credentials, change/restart user deployment, web research, or commit/push. B1 closes admin setup blocker, not live CLI B2. Other features remain honest.

## Owners

- Main: `db.py`, `config.py`, NEW `configuration.py`, configuration service unit tests; dependencies, packaging, final docs/integration/review.
- api-b1: `api.py`, `services.py`, `worker.py`, NEW `admin_routes.py`, API/lifecycle tests incl `test_api.py`. Coordinate interfaces with main.
- ui-b1: `frontend/**` only.
- migrations-b1: NEW `migrations.py`, `src/workbench/alembic/**`, `backup.py`, `admin.py`, migration/backup tests, `docs/UPGRADE-B1.md`. Main owns Dockerfile/compose and root deps; tell main needed changes.

## Models (main creates)

- `IntegrationPolicy`: table `integration_policy`, id int PK=1, revision int=0, rules JSON [], legacy_imported bool false, updated_at timestamp UTC. One immutable revision number with current rules; run snapshots/transactions bind revision. Mutations invalidate old work, do not silently reuse old creds. Optional `Settings.egress_ceiling: list[dict] | None` absent = no configured ceiling; [] = intentionally deny all.
- `OIDCProviderRecord`: table `oidc_providers`, id string100 PK (stable slug), revision int=1, enabled bool=true, display_name string120, config JSON (issuer/client_id/audience/scopes/signing_algorithms/client_type/trust_mode/ca_data), encrypted_secret Text nullable, verification JSON {}, created_at/updated_at timestamps.
- `AuthorizationBinding`: table `authorization_bindings`, (user_id,cluster_id) FK composite PK; generation int default0. Persists after personal revoke, prevents callback resurrection.
- `Cluster.auth_generation` int default0 (global cluster revoke).
- `ClusterCredential`: add provider_revision int0, policy_revision int0, auth_generation int0, cluster_generation int0, storage_mode string20 default persistent, session_hash nullable string64 FK sessions.token_hash ON DELETE CASCADE. Persistent stores NULL session_hash; run_only binds current session. Legacy rev0 must never validate.
- `OIDCTransaction`: add same four revision/generation ints default0; storage_mode default run_only. Existing session_hash binds.
- `Run`: add provider_revision int0, policy_revision int0, auth_generation int0, cluster_generation int0, credential_expires_at nullable timestamp. Current cluster_id resolves provider; run encrypted snapshot contains token expiry too. Old completed observations untouched; legacy active work explicitly cancelled/interrupted during upgrade.
- `WebSession.reauthenticated_at` nullable timestamp. 5-min reauth window enforced on ADMIN mutations; GET /session may expose reauthenticated_until (optional UI handles). Never echo password.

## Configuration service interfaces (main creates)

Use DB as ONLY effective provider/policy source. Settings.providers/allowed_hosts/cidrs retained solely for explicit CLI legacy import; no startup merge/fallback.

`policy_view(session) -> {revision:int,rules:list,legacy_imported:bool}` (missing singleton => revision0/rules[] without write).
`provider_view(row,settings) -> {id,display_name,enabled,revision,issuer,client_id,audience,scopes,signing_algorithms,client_type:'public'|'confidential',trust_mode:'system'|'custom',ca_configured:bool,ca_fingerprint:str|null,client_secret_configured:bool,redirect_uri,verification:dict,created_at,updated_at}`. No secret or CA PEM in reads; CA replacement explicit.
`list_provider_views(session,settings,enabled_only=False) -> list`.
`provider_config(session,provider_id,settings,vault) -> (row,config)` config full for OIDCProvider, requires enabled and configured confidential secret; derives redirect_uri. No network.
`save_provider(session,payload:dict,settings,vault,actor:str,provider_id:str|None=None) -> dict`: create payload has id; edit path id plus expected_revision mandatory. Fields: display_name, enabled, issuer, client_id, audience, scopes, signing_algorithms (default RS256), client_type, trust_mode, ca_data optional base64 PEM (or keep omitted), client_secret optional (or keep omitted), clear_secret bool false. Public client clears secret; system trust clears CA. Pure validation, no DNS. On edit increment revision, clear verification, invalidate affected credentials/flows and cancel queued/request active cancellation under row locks. Audit only field names/revisions, not values/secrets. Return provider_view.
`save_policy(session,payload:{expected_revision:int,rules:list},settings,actor) -> dict`: rules each {id:slug,purpose:'oidc'|'kubernetes'|'registry'|'database',host:exact-host,port:int,cidrs:[str]}. Host validation including IPv4/v6 literal; strict CIDR syntax no localhost/metadata; policy may be empty denies all. Enforce optional ceiling syntactically without DNS. Every changed policy invalidates all auth and active jobs. Increment revision, clear provider verification; no network. Return policy_view.
`policy_http(session,settings,purpose,ca_data=None) -> PolicyHTTP`. Reuses PinnedHTTP but validates host+port+ALL DNS IPs against ONLY matching per-host/purpose rule CIDRs; cross-host unions MUST NOT widen. Public `.allowed_hosts/.allowed_cidrs` for OIDC _check_endpoint precheck; request methods independently enforce actual matched rules. `.validate_endpoint(url)->list[str]` for cluster add; `.get_json/.post_form/.post_json` same interface. No DNS until method call, no network constructor. Production external endpoints HTTPS (port explicit) same hard denials.
`verify_provider(session,provider_id,settings,vault) -> dict` uses saved provider only and explicit bounded calls; returns {status:'passed'|'failed',provider_revision,policy_revision,checked_at,checks:[{check,status,detail}]}; no exception raw output. MUST recheck revisions after network before saving, failures no secrets. At minimum config, discovery/TLS/egress composite if stage precision unavailable, JWT key metadata check; don't claim actual user/RBAC. API rate-limit verification to 1/10s provider, do NOT hold DB lock across network.
`invalidate_access(session,provider_id=None,cluster_id=None,user_id=None,reason='...')`: remove matching ClusterCredential/OIDCTransaction, increment persistent AuthorizationBinding generation for matching user scope and/or cluster.auth_generation (global trust changes), set queued cancelled+clear secret, running cancel_requested+clear secret. Audit caller supplies separate event. DB locks canonical policy -> provider -> cluster -> binding -> run.
`import_legacy_configuration(session,settings,vault,apply=False) -> dict`: preview safe counts/warnings, explicit apply only once, refuse conflicting existing setup; validate static config no external commands, retain IDs, supported policy ports derived from static issuer/cluster server (no DNS). Can conservatively require reauth. Main implementation.

## API endpoints

Existing /api endpoints preserve unless noted. All admin APIs session+administrator, unsafe csrf; mutations require recent reauth. No bootstrap HTTP.
- POST `/api/admin/reauth` {password} -> {reauthenticated_until}; rate limit use same user lockout counters; non-admin denied. Password never logs/errors.
- GET `/api/admin/setup` -> {providers:[provider_view],policy:policy_view,redirect_uri,reauthenticated_until,legacy_configuration_available:bool}. Passive no DNS.
- POST `/api/admin/oidc-providers` -> provider, status201.
- PATCH `/api/admin/oidc-providers/{id}` -> provider (expected_revision).
- PUT `/api/admin/egress-policy` -> policy (expected_revision).
- POST `/api/admin/oidc-providers/{id}/verify` -> verification; require reauth for network probe + rate limit.
- /api/capabilities providers from DB enabled rows, status original features not fabricated. Include `setup_required` bool or `connection_readiness` details if useful.

Authorization:
- POST `/api/clusters/{id}/authorize` body optional {storage_mode:'run_only'|'persistent'} default run_only. GUI selector explicit. Bind transaction to provider/policy revisions and user/cluster generation BEFORE network; check after begin before persist, after exchange before persist; state consumed once. Use provider-specific ca_data from config. Pending revoke/change => reject even successful exchange. Legacy rev0 credentials refused.
- Personal DELETE `/api/clusters/{id}/authorization` all SCAN_ROLES own only; no admin reauth required but csrf. Existing `/credential` admin all-cluster revoke requires reauth.
- Cluster view: status authorization_required/authorized; storage_mode?, credential_expires_at? current user's only.
- Session GET gains reauthenticated_until optional.
- Enqueue: lock/validate personal credential + revisions/generations, immutable expiry saved Run and encrypted snapshot; run_only requires same current session, then atomically delete consumed credential, snapshot survives current job. No duplicate runs via concurrent use. Preflight can use same one-shot lease until enqueue.
- Worker validation uses run snapshot expiry and recorded rev/generations, NOT current ClusterCredential row (consumed run-only absent). Policy dynamically loaded DB. Check revoke/generation every heartbeat; current imported/static Settings no fallback.
- Logout destroys unused run_only credentials tied to session via FK; persistent remains only explicit user-selected.

## Frontend

Settings screen admin only. Reauth prompt before edits/tests; 5min in-memory time. Clear no provider vs request failed vs loading; fix Modes heading (not all available). Form accepts PEM file/text locally converts base64; client_secret input password clears after save, never returned/read/localStorage. OIDC hints for Keycloak/Dex not automatic issuer/client creation. Policy editor exact host, port (443 default, Kubernetes often6443), CIDRs, purpose; show preview before mutation and warning active auth/jobs invalidated.

Cluster wizard can open embedded Settings modal preserving memory-only kubeconfig draft and reload capability providers on close. Main nav Settings also. Non-admin sees contact admin not controls. Add personal credential revoke and explicit once/persistent selection. Render errors sanitized, no mock success. Tests and build.

## Migration owner requirements

Main installs Alembic via uv add. Initial 0.1 baseline schema capture from existing db.py BEFORE new models if needed; generated .py literal metadata migration, not current Base dynamic for baseline. Fresh init uses latest migrations. Old marker recognized only if precise baseline shape, no blind stamp. Explicit admin upgrade command requires backup acknowledged and stop/maintenance; DO NOT execute actual upgrade user stack. Write `backup.py` pg_dump/pg_restore subprocess argv not shell, PG credentials via secure ephemeral pgpass/env not argv, bound timeout/error output, O_EXCL backup no overwrite, restore only EMPTY fresh DB. Local disposable tests allowed independently but no live user stack. Backup contains sensitive data state; never includes master key; verify key distinct. Diagnostics no DB URLs. Current Docker image lacks pg tools; tell main packaging recommendation.

## B1 delivery bounds

No live scanner B2 in this change. Tests must distinguish local mocked OIDC from live Keycloak/Dex lab. Implement core setup + migration fully, don't announce full MVP. Do not silently reset existing state or require user to paste secrets in chat. No commit/push.
