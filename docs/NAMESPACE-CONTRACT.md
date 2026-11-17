# Namespace selection implementation contract — 0.3.0

Historical contract. Version0.4 adds personal kubeconfig token/client-certificate auth without an IdP, plus bounded discovery continuation: [KUBECONFIG-CONTRACT](KUBECONFIG-CONTRACT.md). The OIDC-only requirement and total1000 discovery cap below are historical; read-only probes, explicit scope, ownership and network restrictions remain.

Working project only. No `.local`, personal kubeconfig, live cluster/IdP, adjacent project, web research, deployment restart, commit/push or publishing. Local mocked/disposable tests only. Approved plan: namespace onboarding, not B2 scanners. GET-only preflight; no SSAR POST.

## Shared interfaces and ownership

- schema agent: db.py, migrations.py, backup.py, admin.py, alembic/** (historical snapshots frozen), backend versions pyproject/__init__, schema/backup/admin tests. New schema 0.3.0 / `0003_namespace_selection`.
- collector agent: security.py, scanners.py, new namespaces.py, security/scanner/namespace unit tests.
- lifecycle agent: api.py, services.py, new connection_routes.py/connections.py as needed; test_api.py/test_api_configuration.py plus new connection API tests.
- frontend agent: frontend/** only.
- main: worker.py, test_worker_auth.py/new worker scope tests, documentation and integration/review. Do not modify another owner's files; communicate needed changes.

## Model (schema agent)

Cluster additions:
- `lifecycle` String(20) nonnull default/server_default `ready`, old rows ready.
- `draft_owner_id` nullable String(36) FK users.id, ON DELETE CASCADE (clear on finalize).
- `draft_expires_at` nullable timezone timestamp indexed.
- `context_namespace_hint` nullable String(63).
No extra scope revision: expose auth_generation as `access_revision`. Draft TTL24h, immutable endpoint/provider/CA/context, namespaces=[] until finalized. Personal auth unchanged. Runtime schema gates prevent older binaries running against new schema. Upgrade cancels legacy active work/clears old leases+OIDC flows/credentials, preserves history and policy/provider configuration. Accept 0.1/0.2/0.3 backups with strict frozen schemas; no baseline stamp over B1. admin grant refuses drafts. Recovery/cleanup must never delete a concurrently finalized connection.

## Namespace helpers (collector agent)

`namespaces.py` exports:
- `INVENTORY_VERSION = 1`
- `validate_namespaces(values) -> list[str]`: 1..100 distinct DNS labels; DomainError on invalid, return copy.
- `validate_run_scope(scope, allowed_namespaces) -> dict`: requires exactly namespaces,max_objects,timeout_seconds,inventory_version; version1; validates limits/explicit subset/ready caller; rejects unknown fields/wildcards. Used by worker and API.
- `validate_inventory_url(url, server, namespaces) -> None`: exact endpoint/base path plus current scanners.RESOURCES namespaced paths only; query only limit1..500 and bounded continue; reject unknown/duplicates/origin changes/encoded path tricks. Avoid circular imports via local imports of RESOURCES.
- `discover_namespaces(connection,http) -> dict`: bounded GET /api/v1/namespaces, limit200, <=1000 names/5pages, <=30sec, validate NamespaceList/list metadata/revisions/names/cursors, project name/system/phase. Result `{status:'complete'|'partial'|'forbidden',items:[{name,system,phase?}],complete:bool,limitation:str|null}`. Limit -> explicit partial, malformed/expired snapshot -> sanitized DomainError;403 -> forbidden empty result/manual fallback;401 -> DomainError(code='kubernetes_authentication_required'), never web401. No scanner/resource probing/version calls. Per-request auth wrapper supplied by lifecycle agent.
- All GET/preflight fatal security errors propagate; no local revoked/session/scope error should become recoverable coverage. Preflight rows retain check/status/detail and add code plus namespace/resource/group/verb='list' if convenient. Success code='allowed';403 code='http_403';401 code='http_401' (fatal). TLS transport new code='http_tls'. No unsupported cluster scanning/profile features.
- inspect_kubeconfig returns optional `namespace_hint` only valid DNS label (otherwise sanitized warning/no hint); `validate_connection_metadata(server,ca_data=None)` public security helper strictly matches scanner endpoint syntax and validates CA/TLS without DNS. Manual metadata uses same helper.

## Lifecycle/API (lifecycle agent)

Cluster view adds `lifecycle`, `access_revision`, `namespace_hint` (model context_namespace_hint), `draft_expires_at`; existing personal status/expiry/storage fields preserved. Draft is never runnable/importable/grantable and hidden from ordinary permitted_cluster/clusters_for. Owner-only administrator draft lookup for auth/discovery/preflight/revoke/finalize. No other admin gains ownership by creating auth binding. User-bound drafts, run-only credentials remain session-bound.

Endpoints (relative /api):
- POST `/cluster-drafts` `{name,environment,oidc_provider_id,connection:{kind:'kubeconfig',content,context}|{kind:'manual',context,server,ca_data?:string|null} (manual ca_data is raw PEM, encoded exactly once server-side)}` -> Cluster draft201. No stored raw input/secrets. Max owned drafts bounded (e.g.10), expiry cleanup. GET `/cluster-drafts` -> owned unexpired array; GET/DELETE `/cluster-drafts/{id}` resume/discard.
- Existing POST `/clusters` legacy input retained only as deprecated draft-creation adapter, no ready bypass; ignores supplied namespaces as authority (return namespaces=[]). Update tests accordingly.
- Existing `/clusters/{id}/authorize` accepts ready or owned draft; callback fixed `/#connection-draft=<uuid>` for draft, no arbitrary return URL. Existing recheck/generation protections.
- POST `/clusters/{id}/namespaces/discover` `{}` -> discovery result + namespace_hint. Draft owner or permitted ready SCAN_ROLES own credentials. Nonadmin ready results intersect allowlist. Administrator sees full names for explicit scope-edit flow. No automatic allowlist mutation.
- POST `/clusters/{id}/preflight` `{namespaces}` -> `{coverage}`. Ready subset only; draft explicit candidate allowed. Request wrapper fences every GET and final publication against session/role/owner/grant, auth revisions AND exact attempted credential fingerprint (replacement can occur without rev change). Do not hold locks across I/O. Current policy_http rebuilt each GET. Scope changes/fatal revokes stop, not continue silently.
- POST `/cluster-drafts/{id}/finalize` `{namespaces,expected_access_revision,accept_partial:false}` -> `{cluster,coverage}`. Server reruns selected-only preflight. Accept all allowed, or only allowed+http403 with >=1 allowed AND explicit accept_partial. All-failed or auth/TLS/network/policy/unsupported/not_checked/malformed -> reject. Partial without acknowledgment code preflight_partial; fatal preflight_failed or underlying actionable code. Under canonical locks recheck exact credential/scope/revisions; increment cluster.auth_generation, rebind ONLY verified personal credential to new generation preserving expiry/storage/session; delete outstanding OIDC states; set ready+namespaces, clear owner/expiry. Fences consumed in-flight callbacks.
- POST `/clusters/{id}/scope/preflight` `{namespaces}` -> `{coverage}` admin+recent reauth, allows proposed expansion; candidate only, not mutate.
- PATCH `/clusters/{id}/scope` `{namespaces,expected_access_revision,accept_partial:false}` -> `{cluster,coverage}` admin+recent reauth. Candidate-only rerun preflight; atomic CAS and `invalidate_access` on actual change, cancel stale jobs and credentials; no-op doesn't revoke. Refresh never saves automatically.
- Enqueue scope: `{namespaces,max_objects:1000,timeout_seconds,inventory_version:1}`; encrypted run connection also contains `scope` copy, worker compares both. Preserve current subset/one-shot validation. Unknown cluster-scope/profile inputs rejected via strict models.
- Kubernetes errors must NOT use web401; DomainError `kubernetes_authentication_required` maps409. Do not blindly revoke a fresh credential on stale response.

## Frontend (frontend agent)

Use above API fields. Shared NamespacePicker controlled selection[], options, refresh, filter, counters, select all loaded/filtered, clear, manual fallback, context hint/system badges, missing-preserved and incomplete list states. New selection empty, including run/preflight; editing existing allowlist initializes explicit saved values. Limit100 selection; never silent truncate. Known system names only. Changes invalidate preflight/partial acknowledgment; reject/ignore stale async results. Run choices only saved allowlist, not discovered universe.

Wizard metadata->draft->own OIDC->discovery->checkbox/manual->preflight->finalize, same-origin hash resume without storage/raw input. Settings integration preserved. Manual mode endpoint/context/PEM CA or system trust, OIDC only no raw creds/TLS bypass. Auth default run_only. Closed draft can resume from own drafts list; abort explicit action. All fatal errors truthful; forbidden discovery alone manual fallback. Scope editing uses admin reauth component, expected_access_revision and new scope APIs. Show cluster scans unsupported, no functional opt-in. Run preflight selected scope before submitting, stale coverage reset, partial warning/explicit acknowledgment. Store selected cluster ID not stale object; use fresh metadata after reload.

## Validation

Baseline: `PYTHONPATH=src uv run --frozen pytest -q`:590 passed. Frontend `bun run --cwd frontend test`:93 pass/255 assertions; build passed. Ruff command appears to have preset selecting B008 etc despite --isolated; capture baseline and use explicit project-compatible selection. Use existing dependencies/no new platform, Bun/happy-dom not Vitest. Tests self-contained no real credentials/network. No current user DB migration or deployment restart.
