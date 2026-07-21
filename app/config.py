import os


def _required(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(f"{name} environment variable is not set")

    return value


OIDC_ISSUER = os.getenv("OIDC_ISSUER", "https://openidx.tdv.org")
OIDC_DISCOVERY_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"

OIDC_CLIENT_ID = _required("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = _required("OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = os.getenv(
    "OIDC_REDIRECT_URI",
    "http://localhost:8000/callback",
)
OIDC_SCOPE = os.getenv("OIDC_SCOPE", "openid profile email")

# Expected "aud" on incoming access tokens. Defaults to the client id; override
# when the provider issues tokens for a separate API audience.
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", OIDC_CLIENT_ID)

# Signs the short-lived session cookie that carries the PKCE code_verifier
# between /auth/login and /callback.
SESSION_SECRET = _required("SESSION_SECRET")

# A Secure cookie is never sent over plain HTTP, which would break the login
# round-trip on a http://localhost redirect URI. Keep this on in production.
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() != "false"

