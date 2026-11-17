"""Opt-in real PostgreSQL recovery smoke, isolated from any user deployment.

Requires prebuilt amberdata-workbench-maintenance:0.2.0-local and PostgreSQL image.
Creates a uniquely named internal network/container/volume; removes only those.
"""

import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = r"""
import base64, secrets, tempfile
from pathlib import Path
from datetime import datetime, UTC, timedelta
import sqlalchemy as sa
from workbench.alembic.schema_v01 import metadata
from workbench.migrations import init_database, upgrade_database, verify_schema, assert_empty_database
from workbench.backup import backup_database, restore_database, verify_database_key
from workbench.config import Settings
from workbench.configuration import save_provider
from workbench.db import database, User
from workbench.domain import DomainError
from workbench.security import Vault

password=Path('/run/secrets/test-password').read_text().strip()
url=sa.URL.create('postgresql+psycopg',username='workbench',password=password,host='db',port=5432,database='workbench')
control=sa.create_engine(url,isolation_level='AUTOCOMMIT')
with control.connect() as c:
    for name in ('source_v01','restore_v01','source_v02','restore_v02','wrong_key'):
        c.exec_driver_sql('CREATE DATABASE '+name)
control.dispose()
engines={name:sa.create_engine(url.set(database=name),poolclass=sa.pool.NullPool) for name in ('source_v01','restore_v01','source_v02','restore_v02','wrong_key')}
key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
vault=Vault(key)
old=metadata()
now=datetime.now(UTC)
source=engines['source_v01']
with source.begin() as c:
    old.create_all(c)
    c.execute(old.tables['workbench_schema'].insert().values(version='0.1.0'))
    c.execute(old.tables['users'].insert().values(id='user1',username='legacy-admin',password_hash='not-a-real-password',role='administrator',active=True,failed_logins=0))
    c.execute(old.tables['clusters'].insert().values(id='cluster1',name='legacy-cluster',environment='lab',context='lab',server='https://kube.example.test',oidc_provider_id='legacy',namespaces=['demo'],created_at=now))
    c.execute(old.tables['cluster_grants'].insert().values(user_id='user1',cluster_id='cluster1'))
    c.execute(old.tables['cluster_credentials'].insert().values(user_id='user1',cluster_id='cluster1',encrypted=vault.encrypt({'id_token':'synthetic-token'},'credential:user1:cluster1'),expires_at=now+timedelta(minutes=10)))
    c.execute(old.tables['runs'].insert().values(id='run1',cluster_id='cluster1',actor_id='user1',status='queued',stage='prepare',scope={'namespaces':['demo']},credential=vault.encrypt({'id_token':'synthetic-token'},'run:run1'),cancel_requested=False,created_at=now,coverage=[],limitations=[],versions={},source='api'))
with source.connect() as c:
    assert verify_schema(c)=='0.1.0'
    assert verify_database_key(c,key)==2
with tempfile.TemporaryDirectory(prefix='recovery-',dir='/tmp') as tmp:
    archive=Path(tmp)/'baseline.dump'
    result=backup_database(source,archive,key,offline_confirmed=True)
    assert archive.is_file()
    assert archive.with_name(archive.name+'.manifest.json').is_file()
    restore_database(engines['restore_v01'],archive,key,offline_confirmed=True)
    with engines['restore_v01'].connect() as c:
        assert verify_schema(c)=='0.1.0'
        assert verify_database_key(c,key)==2
        assert c.execute(sa.text('SELECT username FROM users')).scalar_one()=='legacy-admin'
    try:
        restore_database(engines['wrong_key'],archive,base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),offline_confirmed=True)
        raise AssertionError('Wrong key accepted')
    except DomainError:
        with engines['wrong_key'].connect() as c: assert_empty_database(c)
    print('PASS: real pg_dump/pg_restore legacy snapshot; wrong key rejected before restore',flush=True)
    preview=upgrade_database(engines['restore_v01'])
    assert not preview['applied'] and preview['from_version']=='0.1.0'
    applied=upgrade_database(engines['restore_v01'],apply=True,backup_confirmed=True,offline_confirmed=True)
    assert applied['applied']
    with engines['restore_v01'].connect() as c:
        assert verify_schema(c)=='0.2.0'
        assert c.execute(sa.text('SELECT username FROM users')).scalar_one()=='legacy-admin'
        assert c.execute(sa.text('SELECT count(*) FROM cluster_grants')).scalar_one()==1
        assert c.execute(sa.text('SELECT count(*) FROM cluster_credentials')).scalar_one()==0
        assert c.execute(sa.text('SELECT status FROM runs')).scalar_one()=='cancelled'
    print('PASS: guarded 0.1->0.2 upgrade preserves identities/ACL; legacy auth revoked and queued job cancelled',flush=True)
    init_database(engines['source_v02'])
    settings=Settings(database_url=url.set(database='source_v02').render_as_string(hide_password=False),master_key=key)
    sessions=sa.orm.sessionmaker(engines['source_v02'])
    with sessions.begin() as s:
        save_provider(s,{'id':'lab','display_name':'Synthetic provider','issuer':'https://idp.example.test','client_id':'workbench','client_type':'confidential','client_secret':'synthetic-only-secret','trust_mode':'system'},settings,vault,'smoke')
    head_archive=Path(tmp)/'b1.dump'
    backup_database(engines['source_v02'],head_archive,key,offline_confirmed=True)
    restore_database(engines['restore_v02'],head_archive,key,offline_confirmed=True)
    with engines['restore_v02'].connect() as c:
        assert verify_schema(c)=='0.2.0'
        assert verify_database_key(c,key)==1
    print('PASS: B1 provider secret restores with revision-bound vault key',flush=True)
for engine in engines.values(): engine.dispose()
"""


def main():
    identifier = "workbench-recovery-smoke-" + secrets.token_hex(4)
    network, volume, container = (
        identifier + "-net",
        identifier + "-data",
        identifier + "-db",
    )
    docker = ["docker", "--context", "desktop-linux"]

    def call(*args, **kwargs):
        return subprocess.run(
            [*docker, *args], check=True, text=True, timeout=240, **kwargs
        )

    with tempfile.TemporaryDirectory(prefix=identifier + "-") as temporary:
        secret = Path(temporary) / "password"
        secret.write_text(secrets.token_urlsafe(36), encoding="ascii")
        secret.chmod(0o600)
        network_created = volume_created = container_created = False
        try:
            call(
                "network",
                "create",
                "--internal",
                "--label",
                "workbench.disposable=true",
                network,
                capture_output=True,
            )
            network_created = True
            call(
                "volume",
                "create",
                "--label",
                "workbench.disposable=true",
                volume,
                capture_output=True,
            )
            volume_created = True
            call(
                "run",
                "-d",
                "--name",
                container,
                "--label",
                "workbench.disposable=true",
                "--network",
                network,
                "--network-alias",
                "db",
                "--mount",
                f"type=volume,source={volume},target=/var/lib/postgresql/data",
                "--mount",
                f"type=bind,source={secret},target=/run/secrets/test-password,readonly",
                "-e",
                "POSTGRES_USER=workbench",
                "-e",
                "POSTGRES_DB=workbench",
                "-e",
                "POSTGRES_PASSWORD_FILE=/run/secrets/test-password",
                "postgres:17.5-bookworm",
                capture_output=True,
            )
            container_created = True
            for _ in range(40):
                ready = subprocess.run(
                    [
                        *docker,
                        "exec",
                        container,
                        "pg_isready",
                        "-U",
                        "workbench",
                        "-d",
                        "workbench",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Disposable PostgreSQL did not become ready")
            call(
                "run",
                "--rm",
                "-i",
                "--network",
                network,
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
                "--mount",
                f"type=bind,source={secret},target=/run/secrets/test-password,readonly",
                "--mount",
                f"type=bind,source={ROOT / 'src'},target=/app/src,readonly",
                "--entrypoint",
                "python",
                "amberdata-workbench-maintenance:0.2.0-local",
                "-",
                input=SCRIPT,
            )
        finally:
            if container_created:
                call("rm", "-f", container, capture_output=True)
            if volume_created:
                call("volume", "rm", volume, capture_output=True)
            if network_created:
                call("network", "rm", network, capture_output=True)
            print(
                "Only disposable recovery smoke resources removed; user deployment unchanged.",
                flush=True,
            )


if __name__ == "__main__":
    main()
