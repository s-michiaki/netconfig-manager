"""Alembic 導入前（create_all で作成された v1.1 相当）のDBが、起動時に正しく最新化されること"""
import sqlite3

import pytest

from app.core import migrate
from app.core.config import settings
from conftest import TMP

V11_SCHEMA = """
CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY, name VARCHAR(128) NOT NULL UNIQUE, hostname VARCHAR(256) NOT NULL,
  platform VARCHAR(64) NOT NULL, port INTEGER NOT NULL, username VARCHAR(128) NOT NULL, password VARCHAR(256) NOT NULL,
  enable_secret VARCHAR(256), description TEXT, is_active BOOLEAN NOT NULL, created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL);
CREATE TABLE config_snapshots (id VARCHAR(36) PRIMARY KEY, device_id VARCHAR(36) NOT NULL REFERENCES devices(id),
  commit_hash VARCHAR(40) NOT NULL, collected_at DATETIME NOT NULL, lines_added INTEGER NOT NULL,
  lines_removed INTEGER NOT NULL, triggered_by VARCHAR(64) NOT NULL);
CREATE TABLE collect_logs (id VARCHAR(36) PRIMARY KEY, device_id VARCHAR(36) NOT NULL REFERENCES devices(id),
  status VARCHAR(7) NOT NULL, message TEXT, started_at DATETIME NOT NULL, finished_at DATETIME);
CREATE TABLE schedules (id VARCHAR(36) PRIMARY KEY, name VARCHAR(128) NOT NULL, cron_expression VARCHAR(64) NOT NULL,
  target VARCHAR(256) NOT NULL, is_active BOOLEAN NOT NULL, created_at DATETIME NOT NULL);
CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE,
  hashed_password VARCHAR(128) NOT NULL, role VARCHAR(32) NOT NULL, is_active BOOLEAN NOT NULL,
  created_at DATETIME NOT NULL);
"""
V11_DATA = """
INSERT INTO devices VALUES ('d1','sw1','10.0.0.1','cisco_ios',22,'u','enc:x',NULL,NULL,1,'2026-01-01','2026-01-01');
"""


@pytest.mark.parametrize("with_users", [True, False], ids=["v1.1", "v1.0"])
def test_legacy_db_is_stamped_and_upgraded(monkeypatch, with_users):
    path = f"{TMP}/legacy-{with_users}.db"
    con = sqlite3.connect(path)
    schema = V11_SCHEMA if with_users else V11_SCHEMA.split("CREATE TABLE users")[0]
    con.executescript(schema + V11_DATA)
    if with_users:
        con.execute("INSERT INTO users VALUES ('u1','admin','hash','admin',1,'2026-01-01')")
    con.commit()
    con.close()

    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{path}")
    migrate.run_migrations()
    migrate.run_migrations()  # 2回目は何もしない（冪等）

    con = sqlite3.connect(path)
    assert con.execute("select version_num from alembic_version").fetchone()[0] == "0011_ping_targets"
    cols = [r[1] for r in con.execute("pragma table_info(devices)")]
    assert "jump_host_id" in cols and "private_key" in cols
    assert con.execute("select name, jump_host_id from devices").fetchall() == [("sw1", None)]  # 既存データは保持
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    assert {"users", "jump_hosts"} <= tables
    if with_users:
        assert con.execute("select username from users").fetchall() == [("admin",)]


def test_empty_db_is_created(monkeypatch):
    path = f"{TMP}/empty.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite+aiosqlite:///{path}")
    migrate.run_migrations()
    con = sqlite3.connect(path)
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    assert {"devices", "users", "jump_hosts", "schedules", "alembic_version"} <= tables
