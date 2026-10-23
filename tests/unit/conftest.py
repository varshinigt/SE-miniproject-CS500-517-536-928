import pytest
from fastapi.testclient import TestClient

from src.dashboard import db
from src.dashboard.app import create_app


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


@pytest.fixture
def add_packet(client, db_path):
    def _add(ts, src="10.0.0.1", dst="10.0.0.2", protocol="TCP", length=60, info=""):
        with db.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO packets (ts, src, dst, protocol, length, info) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, src, dst, protocol, length, info),
            )

    return _add


@pytest.fixture
def add_alert(client, db_path):
    def _add(ts, severity="high", rule="ARP spoofing", description="test alert"):
        with db.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO alerts (ts, severity, rule, description) VALUES (?, ?, ?, ?)",
                (ts, severity, rule, description),
            )

    return _add
