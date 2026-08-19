"""More than one way in.

A tracker whose only door is one provider stops existing when that provider has
a bad day — which is not hypothetical here: an authentication-flow regression
at the provider left this application unreachable for two weeks.

The security question a second provider raises is which keys a token gets
verified against, and who gets to decide that. These tests are about that
decision.
"""
import pytest

from app.auth import provider_for, provider_for_token
from app.config import PROVIDERS, Provider

GOOGLE = Provider(
    key="google",
    label="Google",
    issuer="https://accounts.google.com",
    client_id="google-client",
    client_secret="google-secret",
    audience="google-client",
    scope="openid email profile",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    jwks_url="https://www.googleapis.com/oauth2/v3/certs",
    userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
    logout_url=None,
)


@pytest.fixture()
def two_providers(monkeypatch):
    monkeypatch.setitem(PROVIDERS, "google", GOOGLE)
    return GOOGLE


def _jwt_with_issuer(issuer: str) -> str:
    """A token shaped like a JWT. Never verified — only its `iss` is read."""
    import base64
    import json

    def seg(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{seg({'alg': 'RS256'})}.{seg({'iss': issuer, 'sub': 'x'})}.signature"


# --- what the interface is told --------------------------------------------


def test_only_configured_providers_are_offered(client, monkeypatch):
    """The registry is what is offered — nothing appears without credentials.

    The second provider is removed here rather than assumed absent. Written the
    other way this passed only on a machine that had no Google credentials in
    its environment, and started failing the moment one did: a test about the
    application quietly reporting on the developer's `.env`.
    """
    monkeypatch.delitem(PROVIDERS, "google", raising=False)

    keys = [p["key"] for p in client.get("/auth/providers").json()]

    assert keys == ["openidx"]


def test_a_configured_second_provider_appears(client, two_providers):
    offered = {p["key"]: p["label"] for p in client.get("/auth/providers").json()}

    assert offered == {"openidx": "OpenIDX", "google": "Google"}


# --- starting a login ------------------------------------------------------


def test_login_goes_to_the_named_provider(client, two_providers):
    response = client.get("/auth/login?provider=google", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].startswith(GOOGLE.authorize_url)
    assert "client_id=google-client" in response.headers["location"]
    # PKCE is not optional for either provider.
    assert "code_challenge_method=S256" in response.headers["location"]


def test_login_without_a_provider_uses_the_default(client, two_providers):
    response = client.get("/auth/login", follow_redirects=False)

    assert PROVIDERS["openidx"].authorize_url in response.headers["location"]


def test_an_unknown_provider_is_refused(client, two_providers):
    """Not silently defaulted: a typo would otherwise send the login somewhere
    the user did not choose."""
    assert client.get("/auth/login?provider=evil").status_code == 404


# --- which keys a token is checked against ---------------------------------


def test_a_token_is_matched_to_its_issuer(two_providers):
    assert provider_for_token(_jwt_with_issuer(GOOGLE.issuer)).key == "google"
    assert provider_for_token(
        _jwt_with_issuer(PROVIDERS["openidx"].issuer)
    ).key == "openidx"


def test_an_unrecognised_issuer_falls_back_to_the_default(two_providers):
    """It still has to verify against that provider's keys, which a token from
    somewhere else will not do — the fallback decides where to look, not
    whether to trust."""
    assert provider_for_token(_jwt_with_issuer("https://attacker.test")).key == "openidx"


def test_an_opaque_token_belongs_to_the_default_provider(two_providers):
    """It carries no issuer to read, so it can only have come from a provider
    that issues opaque tokens."""
    assert provider_for_token("not-a-jwt-at-all").key == "openidx"


def test_a_malformed_token_does_not_raise(two_providers):
    for junk in ("", "a.b", "a.!!!.c", "...."):
        assert provider_for_token(junk).key == "openidx"


def test_provider_for_falls_back_rather_than_failing(two_providers):
    assert provider_for(None).key == "openidx"
    assert provider_for("google").key == "google"
    assert provider_for("nope").key == "openidx"


# --- signing out ------------------------------------------------------------


def test_logout_says_so_when_a_provider_cannot_end_its_session(client, two_providers, monkeypatch):
    """Google has no RP-initiated logout. Sending the browser somewhere that
    will not end the session and calling it a sign-out would be a lie."""
    import app.auth as auth

    monkeypatch.setattr(auth, "provider_for", lambda key: GOOGLE)

    body = client.get("/auth/logout").json()

    assert body["logout_url"] is None
    assert body["provider"] == "google"
    assert "oturum sonlandırma" in body["note"]


def test_logout_returns_the_end_session_url_when_there_is_one(client):
    body = client.get("/auth/logout").json()

    assert body["provider"] == "openidx"
    assert body["logout_url"].startswith(PROVIDERS["openidx"].logout_url)
