"""The token handoff, which is where the login either works or quietly does not.

The callback had no tests, and that is exactly where a real second provider
broke it. Everything up to this point was covered — the redirect, the PKCE
challenge, which keys a token is verified against — but nothing checked *which
token the browser is given*, because the fake provider in `test_providers.py`
issues JWTs for everything and the question never came up.

Google does not. Its access token is an opaque string that means nothing
outside Google, so the browser was handed a credential this application cannot
verify: login succeeded, the account was created, and every request afterwards
came back 401.
"""
import base64
import json

import pytest

import app.auth as auth
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

# Shaped like a JWT — three dot-separated parts. Never verified here; the
# signature check is stubbed out, because what is under test is which token
# travels, not whether authlib can read one.
JWT = "header.payload.signature"
OPAQUE = "ya29.a0AfB_byC-opaque-google-access-token"

CLAIMS = {
    "iss": "https://accounts.google.com",
    "sub": "google-user-1",
    "email": "sevval@example.test",
    "name": "sevval",
}


@pytest.fixture()
def exchange(monkeypatch):
    """Stand in for the provider's token endpoint. Set `reply` per test."""
    reply = {}

    class _Response:
        status_code = 200

        @staticmethod
        def json():
            return reply

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **kw):
            return _Response()

    monkeypatch.setattr(auth.httpx, "Client", _Client)
    monkeypatch.setattr(auth, "_claims_from_jwt", lambda token, provider: CLAIMS)
    monkeypatch.setattr(auth, "_claims_from_userinfo", lambda token, provider: CLAIMS)
    monkeypatch.setitem(PROVIDERS, "google", GOOGLE)
    return reply


def _login(client, provider="google"):
    """Start a login so the session carries the provider and code_verifier."""
    client.get(f"/auth/login?provider={provider}", follow_redirects=False)
    return client.get("/callback?code=abc123", follow_redirects=False)


def _stored_token(html: str) -> str:
    """Pull the token out of the handoff script."""
    start = html.index("setItem('securetask_token', ") + len("setItem('securetask_token', ")
    return json.loads(html[start:html.index(");", start)])


def test_an_opaque_access_token_is_not_what_the_browser_gets(client, exchange):
    """Google's access token is opaque: no `iss` to read, no signature to check.
    Handed over, it falls back to the default provider and is checked against
    the wrong keys — which is a 401 on every request after a successful login.
    """
    exchange.update({"access_token": OPAQUE, "id_token": JWT})

    response = _login(client)

    assert response.status_code == 200
    assert _stored_token(response.text) == JWT
    assert OPAQUE not in response.text


def test_a_jwt_access_token_is_still_used(client, exchange, monkeypatch):
    """OpenIDX issues a JWT access token, and that keeps travelling — an
    installation may set OIDC_AUDIENCE to a separate API audience, which the
    id_token would not satisfy."""
    monkeypatch.setattr(auth, "provider_for", lambda key: GOOGLE)
    exchange.update({"access_token": JWT, "id_token": "other.id.token"})

    assert _stored_token(_login(client).text) == JWT


def test_no_verifiable_token_is_refused_rather_than_handed_over(client, exchange):
    """An opaque access token and no id_token: nothing here could be checked on
    a later request. Issuing the credential anyway would mean trusting whatever
    turns up holding it."""
    exchange.update({"access_token": OPAQUE})

    response = _login(client)

    assert response.status_code == 502
    assert OPAQUE not in response.text


def test_the_handoff_script_carries_the_nonce(client, exchange):
    """The policy has no 'unsafe-inline'. Without the nonce this one script is
    blocked, the token is never stored, and the login silently does nothing —
    the same failure as /docs rendering blank."""
    exchange.update({"access_token": OPAQUE, "id_token": JWT})

    response = _login(client)
    nonce = response.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]

    assert f'<script nonce="{nonce}">' in response.text


def test_the_id_token_is_kept_for_logout_not_given_away(client, exchange):
    """It goes into the signed session cookie so logout can send it as
    id_token_hint. When it is also the bearer the browser holds, that is one
    credential doing two jobs — not a second one handed out."""
    exchange.update({"access_token": JWT, "id_token": "logout.hint.token"})

    _login(client)

    # The cookie is base64 payload + signature; decode the payload to read it.
    payload = client.cookies.get("session", "").split(".")[0]
    session = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))

    assert session["id_token"] == "logout.hint.token"
    assert session["provider"] == "google"
