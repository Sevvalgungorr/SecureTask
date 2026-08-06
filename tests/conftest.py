"""Shared test fixtures.

Tests run against a dedicated Postgres database so the schema behaves exactly
like production. Authentication is replaced with a dependency override, so the
tests never contact the OIDC provider — they set "who is logged in" directly.
Before login_as() is called the real dependency runs, so unauthenticated
requests still return 401.
"""
import os

# The test database is the configured one with its name swapped to
# `securetask_test`, so it reuses the same credentials. Must be set before the
# app modules are imported (config/database read the environment at import).
_real = os.environ.get("DATABASE_URL", "")
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or (
    _real.rsplit("/", 1)[0] + "/securetask_test"
    if _real
    else "postgresql+psycopg2://securetask:@localhost:5432/securetask_test"
)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("OIDC_CLIENT_ID", "test-client")
os.environ.setdefault("OIDC_CLIENT_SECRET", "test-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.auth import get_current_user  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.models import User  # noqa: E402
import app.main as main_module  # noqa: E402

engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = main_module.app


@pytest.fixture()
def db():
    """A clean schema for every test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_user(db, username, roles, amr, acr):
    user = User(
        username=username,
        email=f"{username}@example.test",
        oidc_issuer="https://openidx.tdv.org",
        oidc_sub=username,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    # Transient, exactly as get_current_user attaches them from the token: the
    # default is a password-only session, so step-up guards are exercised.
    user.roles = roles
    user.amr = amr
    user.acr = acr
    return user


@pytest.fixture()
def client(db):
    """A TestClient bound to the test DB. Call client.login_as(...) to
    authenticate; without it, requests are unauthenticated (401)."""
    # The rate limiter counts per client address in module-level state, and
    # every test shares one address. Left alone, a long enough suite starts
    # failing on 429 for reasons that have nothing to do with what it tests.
    main_module._hits.clear()
    app.dependency_overrides[get_db] = lambda: db
    test_client = TestClient(app)

    def login_as(username="alice", roles=None, amr=None, acr=None):
        user = _make_user(db, username, roles or [], amr or ["pwd"], acr)
        app.dependency_overrides[get_current_user] = lambda: user
        return user

    def logout():
        app.dependency_overrides.pop(get_current_user, None)

    test_client.login_as = login_as
    test_client.logout = logout

    yield test_client

    app.dependency_overrides.clear()
