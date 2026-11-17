# B1 upgrade and recovery (0.1.0 → 0.2.0)

> Historical B1 procedure. Current 0.3.0 Compose files and maintenance image target the namespace-selection release; use [NAMESPACE-SELECTION.md](NAMESPACE-SELECTION.md) for the supported 0.1/0.2 → 0.3 upgrade. Do not assume the commands below still target 0.2.0 with current source.

B1 moves effective OIDC-provider and egress configuration into PostgreSQL. It does
not enable a live scanner CLI or automatically configure Keycloak/Dex. Static
configuration is **not merged on startup**; import it explicitly or configure it in
administrator Settings after the schema upgrade.

## Safety rules

- Use a dedicated PostgreSQL database. Do not upgrade a live API/worker deployment.
  Stop both, disable automatic restarts/reconnects, and close other database clients.
  An acknowledgement flag does not stop services for you.
- Keep the existing external master-key file safe, separately from the database
  backup. Do not generate a replacement key, include it in a backup archive, paste
  it into a terminal command, or send it in chat.
- Backups include sensitive application state, password hashes, encrypted tokens,
  and possibly sensitive findings. Store both backup files on protected encrypted
  storage, restrict access, and apply your own retention/offsite policy.
- Never use `docker compose down -v`, drop the existing database, delete `.local`,
  run a blind Alembic stamp, or try to bypass a schema mismatch. A schema mismatch
  requires investigation against a copy, not destructive repair.
- The commands below are operator instructions, not automatic actions performed
  by the implementation. No real deployment is modified by the unit tests.

## Administration tools

The normal API/worker image does not need PostgreSQL client programs. The separate
`maintenance` Docker target and `compose.maintenance.yaml` provide PostgreSQL 17
`pg_dump`/`pg_restore`, matching the supplied PostgreSQL 17 deployment. Build the
maintenance target with the project image build workflow before the maintenance
window. If your server major version changes, provide compatible clients too.

The module CLI is `python -m workbench.admin`. It reads the database URL and master
key through `WORKBENCH_DATABASE_URL_FILE` and `WORKBENCH_MASTER_KEY_FILE` (and static
configuration through `WORKBENCH_CONFIG_FILE`). **No key/password CLI arguments
exist.** Do not echo the secret files to diagnose a failure.

For this Mac/Docker Desktop, prepare the maintenance image **before** stopping the old API:

```sh
cd /Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench
export WORKBENCH_UID="$(id -u)" WORKBENCH_GID="$(id -g)"
export WORKBENCH_BACKUP_DIR="$PWD/backups"
mkdir -p "$WORKBENCH_BACKUP_DIR"
chmod 700 "$WORKBENCH_BACKUP_DIR"
docker --context desktop-linux compose -f compose.yaml -f compose.maintenance.yaml build api maintenance
docker --context desktop-linux compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance --help
```

Use the intended **local** Docker context for all following commands. Here it is `desktop-linux`; do not run the procedure against a remote Docker context. The commands below assume that local context. Retain the old `amberdata-workbench:0.1.0-local` image for rollback; the new image is `0.2.0-local`.

Create a dedicated backup directory in advance, owner-writable and not
world/group-writable (recommended mode `0700`), accessible to the configured
`WORKBENCH_UID:WORKBENCH_GID`. Set `WORKBENCH_BACKUP_DIR` to that directory. The
maintenance service mounts it at `/backups`; it does not auto-create a missing host
directory. Backup archive and manifest are always created with mode `0600` and
exclusive creation. Existing files and symlinks are refused, not overwritten.

For a non-Compose installation, run the module with the same secret-file settings
and a writable protected directory. Optional `--pg-dump /path/to/pg_dump`,
`--pg-restore /path/to/pg_restore`, and `--timeout SECONDS` select a client executable
and bounded timeout (1–3600 seconds, default 300). These are not shell commands;
there is no automatic client installation.

## Existing 0.1.0 database

1. Record your current application version and prepare the matching old image for
   rollback. Stop API and workers using your deployment's maintenance procedure;
   leave PostgreSQL running. Prevent other writers from reconnecting. For the supplied local Compose:

   ```sh
   docker --context desktop-linux compose stop api worker
   ```

   This is a maintenance interruption. Do not stop the user's services as a side effect of building/testing code.
2. Run the read-only preview using the B1 maintenance image:

   ```sh
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance upgrade
   ```

   A valid old database must have exactly one `workbench_schema` marker `0.1.0`
   and the captured 0.1 table/column/type/default/key/constraint/index structure.
   A partial, foreign, already-stamped or unexpected schema is refused. The preview
   reports counts only: credentials/flows to invalidate and queued/running work to
   terminate. It does not expose tokens, URLs, or passwords.
3. Produce a new backup with an unused filename:

   ```sh
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance backup /backups/pre-b1.dump --offline-confirmed
   ```

   Keep **both** `pre-b1.dump` and `pre-b1.dump.manifest.json`. The archive is
   PostgreSQL custom format. The adjacent manifest authenticates archive checksum,
   schema version, and key-check metadata with the separately supplied master key.
   The key itself is never stored. Verify that the external key is recoverable
   from a separate secure location. Prefer a restore rehearsal into a separate,
   disposable empty PostgreSQL database before acknowledging the backup.
4. Apply only after the backup and stop prerequisites are actually satisfied:

   ```sh
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance upgrade --apply --backup-confirmed --offline-confirmed
   ```

   The migration holds a PostgreSQL advisory transaction lock. It verifies the
   exact baseline before adopting it into Alembic, changes the schema and legacy
   authorization state in one transaction, and verifies both head markers and the
   resulting structure before commit. Concurrent administration attempts and
   existing connected database clients are refused. The client check is not a
   firewall: the operator must prevent new API/worker connections.
5. Import legacy static configuration explicitly if appropriate:

   ```sh
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance import-legacy
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance import-legacy --apply --offline-confirmed
   ```

   Preview is the default. The configuration service validates the import,
   preserves stable provider IDs, rejects conflicting setup, and permits applying
   it only once. No network or kubeconfig auth plugin is invoked. A broad old
   allowlist may not translate safely: resolve validation warnings instead of
   widening the new per-host/purpose policy. Alternatively configure providers and
   policy manually in administrator Settings after restarting B1.
6. Check `status`, restart **only B1** API/workers, sign in as administrator, review
   policy/providers, reauthenticate for administrator changes, and explicitly test
   the configured provider. Users authorize Kubernetes access again before runs.

   ```sh
   docker --context desktop-linux compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps maintenance status
   docker --context desktop-linux compose up -d --wait api worker
   ```

   Open `http://127.0.0.1:8080` and use **Settings → Connections**. Do not create the first user again: existing accounts are retained. If legacy file settings were empty, skip `import-legacy --apply` and configure the new DB-managed settings through this UI.

### What is preserved and invalidated

Preserved: account IDs and password hashes, roles, sessions, clusters and provider
references, user/cluster grants, findings/dispositions, observations, completed
run metadata, and existing audit history. A schema upgrade audit event is added.

Invalidated deliberately: old revisionless personal cluster credentials and
pending OIDC flows are deleted; queued runs become `cancelled`, running runs become
`interrupted`, leases and snapshots are cleared. Any stray credential snapshot on
a completed run is also removed without changing its findings/observations or
other history. The newly created provider registry is empty and the initial
policy denies all. Nothing silently reuses old credentials.

The stop prerequisite matters: changing a row cannot kill a process already using
a token. Do not treat the invalidation as permission to leave old workers running.
There is no destructive downgrade command and invalidated tokens cannot be
recovered through a down migration.

## Fresh installations

`init-db` initializes the **latest** Alembic schema in an empty dedicated database.
Repeating it on a verified latest database is harmless. On 0.1.0 it refuses and
requires the explicit upgrade procedure above; on a partial/foreign database it
refuses without creating missing tables. It never runs current ORM `create_all`
against existing user state. Bootstrap `create-user` and `grant` remain available
and require the latest schema; no default administrator password is introduced.

## Restore / rollback

1. Keep API/workers stopped. Provision a **different, empty dedicated PostgreSQL
   database** and point the maintenance command's database-URL secret file to that
   target. Supply the original master-key file separately. Do not run `init-db`
   first: even an initialized empty Workbench database is not an empty restore
   target. The existing source database should remain untouched for investigation.
2. Mount the protected archive and matching manifest and run against that target:

   ```sh
   python -m workbench.admin restore /protected/pre-b1.dump --offline-confirmed
   python -m workbench.admin status
   ```

   Or use the Compose maintenance service **only after explicitly configuring its
   secret-file mounts for the new target**. The default Compose URL still points
   to your original database; this document does not redirect it automatically.
3. Wrong keys, altered manifests, mismatching archive checksums, and unsafe input
   permissions are rejected before opening the restore target. Nonempty targets
   are refused. `pg_restore` runs without shell, `--clean` or `--create`; it uses
   `--single-transaction --exit-on-error`. Its connection password is supplied via
   an ephemeral `0600` pgpass in a `0700` directory, not a URL/argv/log message.
4. After restore, the utility verifies the schema and decryptability of all
   encrypted fields using their original purpose/revision bindings. A restored
   0.1 backup remains 0.1; run the matching old image for rollback, or explicitly
   upgrade the restored database before running B1. Do not attach old code to a
   B1 database.
5. Start application clients only after verification succeeds. If post-restore
   verification fails, **keep the target offline**. The helper does not drop or
   erase it. Investigate or provision another empty target. Never retry with a
   different key against a live deployment.

## Guarantees and limits

- Backup takes SHARE locks on application tables and passes an exported PostgreSQL
  snapshot to `pg_dump`, so metadata/key validation and archived rows agree. Other
  connected clients are rejected, but operators still control maintenance and
  connectivity. Tables are not locked indefinitely: lock wait and subprocess
  runtime are bounded.
- The database URL is never logged or passed to client tools. Connection identity
  and supported TLS options are passed in a minimal environment; the password is
  in temporary pgpass. Child stderr is discarded rather than collected without
  bounds or leaking credentials. Failures deliberately provide generic diagnostics.
- If the source contains no encrypted values, there is no way to prove that a
  supplied key was its historical key. `status` says so. A newly created backup
  still authenticates the supplied key and wrong-key restore still fails.
- Backup archive + manifest are a pair, not an atomic multi-file filesystem commit.
  A crash can leave partial files; restore rejects missing/invalid metadata. Use
  another filename for a retry and investigate partial files manually. Ordinary
  command failures remove only files created by that invocation.
- PostgreSQL restore executes archive SQL. Restore only your own trusted backups;
  possessing the master key is not a sandbox for arbitrary archives. A successful
  `pg_restore` commits before post-verification; verification failure quarantines
  the target rather than claiming an automatic rollback after commit.
- No key rotation, object-store integration, scheduler, retention manager,
  PostgreSQL role/ownership backup, or automated disaster-recovery cutover is
  implemented. `--no-owner --no-acl` restores objects under the target operator;
  target database permissions are an operator responsibility. Application ACL rows
  remain part of the dump.
- `tests/test_migrations.py` uses isolated SQLite for shape, preservation, and DDL
  rollback tests. `tests/test_backup.py` uses safe subprocess mocks. The separate
  `tests/smoke_migrations.py` was also executed on disposable PostgreSQL 17.5 and passed:
  real `pg_dump`→`pg_restore` for 0.1 and 0.2, wrong-key rejection before restore,
  preservation of account/ACL through 0.1→0.2, explicit legacy auth invalidation,
  and revision-bound provider-secret restoration. Only its own temporary resources
  were created/removed. This is not a rehearsal of the user's current database;
  test restoration of your actual backup before relying on it.

  ```sh
  PYTHONPATH=src uv run --frozen python tests/smoke_migrations.py
  ```
