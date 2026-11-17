# Scanner support and boundaries

## Implemented, without scanner executables

- `preflight(connection, scope, http)` performs only `GET ...?limit=1` probes for every explicitly named namespace and each supported resource type. It does not create a SelfSubjectAccessReview or discover additional namespaces. A successful probe means list access, not completed security coverage, and an empty collection does not prove that a manually entered namespace exists.
- `discover_namespaces(connection, http)` is a separate explicitly requested onboarding operation: bounded paginated `GET /api/v1/namespaces`, names/phase projection only, no workload inspection. A discovery 403 permits manual namespace entry; it does not establish whether namespaced resource reads are allowed. Discovery never expands a saved connection or run scope.
- `scan_inventory(connection, scope, http, cancelled)` reads namespaced Deployments, StatefulSets, DaemonSets, Pods, Services, NetworkPolicies, Roles, RoleBindings and ServiceAccounts using the supplied `PinnedHTTP`. Callers must construct that client using the cluster CA and administrator endpoint policy; this module never substitutes a permissive HTTP client.
- Linux workload checks cover explicit privileged mode, host namespaces, explicit UID 0, absent non-root enforcement and privilege-escalation configuration. Init and ephemeral containers are included. Controller templates and running Pod specifications are distinct observations; no claim of process identity or exploitation is made.
- Non-workload lists are inventory/access coverage only, not Service, NetworkPolicy or RBAC policy assessments. Windows workload checking is explicitly unsupported. These built-in checks are not Kubescape or CIS compliance.

No Secret, ConfigMap, logs, exec, node, cluster-role or cluster-role-binding endpoint is requested. No mutation method is called. Listed workload objects can contain environment values in API responses, but only allowlisted identity/security fields and validated SHA-256 image references reach findings; environment, command, annotation, label, status, volume and embedded manifest contents are discarded. Inventory bodies are not persisted by this module.

### Bounds and failure behavior

- Scope must contain 1–100 distinct, explicit valid namespace names; wildcards and all-namespace requests are rejected.
- Global object budget defaults to 1,000 and is capped at 10,000; pages request at most 100 objects. Caps are 100 pages per resource and 1,000 pages globally, including empty pages.
- Deadline is 1–600 seconds, default 300. Cancellation is checked between requests and objects. In-flight synchronous GET cancellation is cooperative and bounded by `PinnedHTTP` request timeouts; no claim of immediate socket cancellation is made.
- Pagination tokens stay opaque and are URL-encoded, never interpreted as paths. Repeated cursors, duplicate UIDs, inconsistent list revisions, wrong namespaces, malformed lists and over-limit responses mark coverage incomplete. There are no retries of expired or throttled snapshots.
- 401, rate limiting, endpoint rejection and transport/time failures halt further requests; subsequent resource coverage is `not_checked`. 403 is reported per resource; other allowed namespaces/kinds can still be checked. 404/405 are `unsupported`. All HTTP details are fixed sanitized text using the security module's `DomainError.code`, never API responses or exception messages.
- Findings are capped at 2,000, with an explicit coverage error if additional observations are omitted. No silently truncated result is called complete.

## Offline imports

`parse_report(scanner, report)` accepts decoded JSON objects. The API may impose a smaller upload limit (currently 1 MiB); this parser additionally caps the JSON tree at 8 MiB estimated serialized size, 100,000 nodes and depth 32, rejects non-JSON values, cycles and repeated Python container references, and caps output findings at 2,000.

Only these narrow structures are supported:

| Scanner | Supported report structure | Retained observations |
| --- | --- | --- |
| Trivy | `SchemaVersion: 2`, `ArtifactType: container_image`, `ArtifactName`, `Results[]` with `Class: os-pkgs` or `lang-pkgs`, `Type`, `Target`, `Vulnerabilities[]` | Vulnerability identifier, severity, package/version/fixed version, package path/target, manifest/config/layer digests. `Trivy.Version` is retained when supplied; otherwise scanner version is `not_provided`. |
| kube-bench | `Controls[]` with `id`, optional benchmark `version`, `tests[]` with `section` and `results[]` with `test_number`, `status: PASS/FAIL/WARN/INFO` | FAIL observations; WARN/INFO manual-review observations mark evaluation incomplete. Benchmark version is not misrepresented as executable version. PASS is coverage only. |
| Kubescape | Resource-results report with `resources[]`, `results[]`, `resourceID` in group/version/kind/namespace/name form, `controls[]` containing `controlID: C-...`, `status: {status: passed/failed/skipped/error}` | Failed control identifiers and resource location/UID. Optional string severity is normalized; missing severity remains `unknown`, never invented. `metadata.toolVersion` is retained when supplied. Embedded resource objects are not retained. Skipped/error controls do not count as evaluated. |

Legacy Kubescape framework/rule reports, summary-only formats, Trivy filesystem/configuration/secret reports and unknown roots are rejected rather than guessed. These fixtures establish the implemented local schema contract, not end-to-end compatibility with any installed/current scanner release. Malformed rows with valid sibling observations produce explicit partial/error coverage; wholly malformed reports raise a sanitized `DomainError`. Empty report containers do not establish completed coverage. A completed *parsing* entry never means a completed cluster scan.

Imported reports always carry `origin: imported`, `source: imported_report`, `provenance_verified: false` and a `not_checked` provenance coverage entry. Selecting a cluster in the API does not verify that the report came from that cluster. Reported versions, digest identities and findings are untrusted claims. An image config `ImageID` is preserved as `image_config_digest`, **not** mislabeled as a manifest digest.

All report titles/recommendations are fixed application text. Arbitrary scanner descriptions, remediation prose, audit commands, actual values, stdout, stderr, URLs, secret matches and manifests are omitted. Retained identifier fields use bounded allowlists; unsafe or secret-like values are replaced in full with `[redacted]`, without prefixes or suffixes. This is conservative projection, not a promise to detect every possible secret encoded in an otherwise valid identifier. UI/export code must still use safe text rendering and context-appropriate escaping.

## Unavailable live adapters

Trivy, kube-bench and Kubescape live CLI adapters are **unavailable** pending verified pinned binaries, flags, schema/default behavior, output limits and isolation. No PATH lookup, installation, download or subprocess occurs. `run_cli()` always raises `scanner_unavailable` for known scanners. `subprocess_argv()` only constructs a bounded literal argument vector for a future adapter; it does not execute or verify a binary and must never be passed to a shell.

No real cluster, IdP or scanner executable was contacted for this implementation. Tests are offline fake-HTTP and local malicious/partial JSON fixtures.
