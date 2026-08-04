"""Sign-out hands back the provider's end-session URL.

Dropping our own token only signs the user out of this app — the provider's SSO
session would stay open and the next login would be granted silently. So logout
must point the browser at the provider's end_session endpoint as well.
"""
from urllib.parse import urlparse

from app.config import OIDC_ISSUER


def test_logout_returns_the_provider_end_session_url(client):
    client.login_as("alice")

    response = client.get("/auth/logout")
    assert response.status_code == 200

    url = urlparse(response.json()["logout_url"])
    base = f"{url.scheme}://{url.netloc}{url.path}"
    assert base == f"{OIDC_ISSUER}/oauth/logout"


def test_logout_works_without_authentication(client):
    """A user whose token already expired must still be able to sign out."""
    client.logout()

    assert client.get("/auth/logout").status_code == 200
