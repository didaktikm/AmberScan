# Kubeconfig-only implementation contract — 0.5.0

This approved change supersedes authentication/provider requirements in CONTRACT.md, B1-CONTRACT.md, NAMESPACE-CONTRACT.md and KUBECONFIG-CONTRACT.md. Historical schemas/revisions remain immutable. Existing isolation, ownership, TLS/egress, access controls and namespace-scope restrictions remain.

## Runtime interfaces

- Only `auth_type: kubeconfig`; imported normalized auth is inline token or client_certificate. No provider identifier/revision, authorization redirect, callback, provider CRUD/verification, or legacy id_token fallback.
- Preserve local Workbench password login, same-origin cookies/CSRF, administrator reauthentication, cluster grants and private per-user credentials.
- Draft creation accepts only kubeconfig connections. Existing credential replacement retains expected access revision and exact endpoint/CA/context matching. Reject legacy provider inputs; removed API routes return JSON404 rather than SPA HTML.
- Namespace discovery, encrypted continuation, explicit selection≤100, selected-only GET preflight and finalize remain. Listing names does not grant workload access; no implicit namespace selection.
- Retain run_only≤1h/session and persistent≤24h/source expiry, generation/session/grant fences and policy→cluster→binding lock ordering. Immutable run auth/scope checked before/after requests and before publication.
- Preserve strict bounded YAML, no exec/auth-provider execution or loaded file paths, no proxy/insecure TLS, verified mTLS and DNS pinning. JWT expiry hint only shortens token lifetime; it does not verify identity.
- Settings expose egress and administrator reauthentication, not providers. Legacy ceiling conversion never widens permissions: empty remains deny-all. Provider config must not load secret files.

## Migration and recovery

- Schema0.5.0/revision0005_remove_oidc. Preserve old frozen schemas/revisions and historical backup key verification.
- Remove provider/transaction tables and provider-specific columns/revisions. Keep auth_type constrained to kubeconfig.
- Preserve users, cluster IDs/metadata/CA/context, scope, grants, findings/results/audit. Metadata conversion does not create credentials.
- Explicit offline upgrade invalidates ALL personal Kubernetes credentials and flow/cursor authorization, clears encrypted run snapshots/leases, cancels queued and interrupts running jobs, advances policy/cluster/binding revisions. User must reimport kubeconfig into the saved connection after upgrade.
- Remove only obsolete provider-purpose policy rules; preserve remaining restrictions.
- Retain old images/source, create offline backup+manifest, verify real restore into separate empty DB before upgrading the actual deployment. Keep original master key; never down-v, reset user account, or attach old runtime to new schema.

## Execution boundary for this task

The user authorized local Docker Desktop update in this repository/project and a bounded read-only verification of the already saved Kubernetes connection. This supersedes earlier no-restart/no-live-check restrictions only for this task. Kubernetes GET discovery/preflight is allowed through the ordinary user's authenticated application session, within saved scope. No workload scan is implied; no Kubernetes resource/RBAC/IdP mutations, TLS bypass, automatic egress widening, external publishing, commit/push or adjacent-project changes.

Source changes and disposable tests do not establish successful deployment or live connectivity. Report executed checks, failures, skips, and required user login/reimport separately.
