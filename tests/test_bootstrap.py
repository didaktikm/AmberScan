"""First-run operations are non-destructive and never create default passwords."""

import base64
import json
import stat

import pytest
from sqlalchemy import inspect, select, text

from workbench.admin import create_user, init_database
from workbench.db import User, database
from workbench.domain import DomainError
from workbench.security import Vault, password_verify
from workbench.setup_local import prepare_local


def test_local_setup_generates_restricted_files_without_output(tmp_path, capsys):
    folder = tmp_path / "local"
    assert prepare_local(folder)
    assert capsys.readouterr().out == ""
    for path in folder.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    master_key = (folder / "master-key").read_text().strip()
    assert len(base64.urlsafe_b64decode(master_key)) == 32
    Vault(master_key)
    password = (folder / "postgres-password").read_text().strip()
    assert len(password) >= 40
    assert password in (folder / "database-url").read_text()
    config = json.loads((folder / "config.json").read_text())
    assert "providers" not in config
    assert config["allowed_hosts"] == []
    assert config["allowed_cidrs"] == []
    assert config["public_origin"] == "http://127.0.0.1:8080"


def test_local_setup_repeat_keeps_key_and_password(tmp_path):
    assert prepare_local(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert not prepare_local(tmp_path)
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()}


def test_partial_setup_never_overwrites_files(tmp_path):
    key = tmp_path / "master-key"
    key.write_text("existing key")
    with pytest.raises(DomainError, match="Partial"):
        prepare_local(tmp_path)
    assert key.read_text() == "existing key"
    assert len(list(tmp_path.iterdir())) == 1


def test_symlink_setup_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(DomainError, match="symlink"):
        prepare_local(link)
    assert not list(target.iterdir())


def test_readable_secret_setup_rejected(tmp_path):
    prepare_local(tmp_path)
    (tmp_path / "master-key").chmod(0o644)
    with pytest.raises(DomainError, match="0600"):
        prepare_local(tmp_path)


@pytest.fixture
def storage():
    engine, sessions = database("sqlite+pysqlite:///:memory:")
    yield engine, sessions
    engine.dispose()


def test_schema_initialization_repeat_is_safe(storage):
    engine, sessions = storage
    init_database(engine)
    with sessions.begin() as session:
        create_user(session, "operator", "A-test-only-password-42", "administrator")
    init_database(engine)
    with sessions() as session:
        user = session.scalar(select(User).where(User.username == "operator"))
        assert user is not None
        assert password_verify("A-test-only-password-42", user.password_hash)
        assert user.role == "administrator"
    assert "workbench_schema" in inspect(engine).get_table_names()


def test_existing_database_without_marker_is_not_modified(storage):
    engine, _ = storage
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE other_data (id INTEGER PRIMARY KEY)"))
    with pytest.raises(DomainError, match="not empty"):
        init_database(engine)
    assert inspect(engine).get_table_names() == ["other_data"]


def test_wrong_schema_version_refused(storage):
    engine, _ = storage
    init_database(engine)
    with engine.begin() as connection:
        connection.execute(text("UPDATE workbench_schema SET version='future'"))
    with pytest.raises(DomainError, match="Unsupported"):
        init_database(engine)


def test_duplicate_user_does_not_reset_password(storage):
    engine, sessions = storage
    init_database(engine)
    with sessions.begin() as session:
        create_user(session, "operator", "Original-test-password-42", "administrator")
    with (
        sessions.begin() as session,
        pytest.raises(DomainError, match="already exists"),
    ):
        create_user(
            session, "operator", "Replacement-test-password-42", "administrator"
        )
    with sessions() as session:
        user = session.scalar(select(User))
        assert password_verify("Original-test-password-42", user.password_hash)


@pytest.mark.parametrize(
    "username,password,role",
    [
        (" x ", "Long-test-password", "viewer"),
        ("user", "short", "viewer"),
        ("user", "Long-test-password", "unknown"),
    ],
)
def test_invalid_account_rejected(storage, username, password, role):
    engine, sessions = storage
    init_database(engine)
    with sessions.begin() as session, pytest.raises(DomainError):
        create_user(session, username, password, role)
