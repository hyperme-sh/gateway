import ssl

import pytest
from asyncpg import connect_utils
from sqlalchemy.pool import NullPool

from hypermesh_gateway_service.private_storage import private_engine


async def test_new_connections_read_the_current_file_for_each_owner(monkeypatch, tmp_path):
    class ConnectionObserved(Exception):
        pass

    observed = []

    async def observe(*, params, **kwargs):
        assert params.ssl.check_hostname
        assert params.ssl.verify_mode == ssl.CERT_REQUIRED
        observed.append((params.user, params.database, params.password))
        raise ConnectionObserved

    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.setattr(connect_utils, "_connect_addr", observe)

    def write_password(owner, token):
        path = tmp_path / f"{owner}.pgpass"
        next_path = path.with_suffix(".new")
        next_path.write_text(f"pg.example.test:5432:{owner}:{owner}:{token}\n")
        next_path.chmod(0o600)
        next_path.replace(path)
        return path

    history = private_engine("postgresql://history@pg.example.test/history", "history_fixture",
                             passfile=str(write_password("history", "history-first")), poolclass=NullPool)
    training = private_engine("postgresql://training@pg.example.test/training", "training_fixture",
                              passfile=str(write_password("training", "training-first")), poolclass=NullPool)
    try:
        for engine in (history, training):
            with pytest.raises(ConnectionObserved):
                await engine.connect()
        write_password("history", "history-second")
        with pytest.raises(ConnectionObserved):
            await history.connect()
        assert observed == [
            ("history", "history", "history-first"),
            ("training", "training", "training-first"),
            ("history", "history", "history-second"),
        ]
    finally:
        await history.dispose()
        await training.dispose()


@pytest.mark.parametrize("url,path", [
    ("postgresql://owner:fixture@pg.example.test/owner", "/run/owner.pgpass"),
    ("postgresql://owner@pg.example.test/owner?sslmode=disable", "/run/owner.pgpass"),
    ("postgresql://owner@pg.example.test/owner", "owner.pgpass"),
])
def test_file_mode_refuses_an_alternate_password_or_tls_configuration(monkeypatch, url, path):
    monkeypatch.delenv("PGPASSWORD", raising=False)
    with pytest.raises(ValueError, match="password-free PostgreSQL URL"):
        private_engine(url, "owner_fixture", passfile=path)


def test_file_mode_refuses_an_ambient_password(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "fixture")
    with pytest.raises(ValueError, match="password-free PostgreSQL URL"):
        private_engine("postgresql://owner@pg.example.test/owner", "owner_fixture", passfile="/run/owner.pgpass")
