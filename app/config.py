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

# Where the provider sends the browser after it ends the SSO session. Must be
# registered with the provider; leave empty to let it show its own logout page.
OIDC_POST_LOGOUT_REDIRECT_URI = os.getenv("OIDC_POST_LOGOUT_REDIRECT_URI", "")

# Expected "aud" on incoming access tokens. Defaults to the client id; override
# when the provider issues tokens for a separate API audience.
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", OIDC_CLIENT_ID)



def _csv(name: str, default: str) -> frozenset[str]:
    return frozenset(
        part.strip().lower() for part in os.getenv(name, default).split(",") if part.strip()
    )


# --- Step-up authentication -----------------------------------------------
#
# Accepting a risk means a finding stays open forever by decision. That is the
# one action here that cannot be undone by fixing something later, so it asks
# for a second factor rather than trusting whatever session is already open.
#
# Which values prove a second factor is provider-specific: OIDC defines the
# `amr` (methods used) and `acr` (context class) claims but not their contents.
# These lists must be checked against what the provider actually issues.
STEP_UP_REQUIRED = os.getenv("STEP_UP_REQUIRED", "true").lower() != "false"

# `pwd` is deliberately absent: a password is the first factor, not a second.
OIDC_MFA_AMR = _csv(
    "OIDC_MFA_AMR",
    "mfa,otp,push,mfa_push,totp,sms,hwk,swk,webauthn,fido,u2f",
)

# Empty by default: an acr value only means "step-up" if the provider says so,
# and guessing one would silently weaken the check.
OIDC_MFA_ACR = _csv("OIDC_MFA_ACR", "")

# --- Monitoring -------------------------------------------------------------
#
# Checks are outbound connections the server makes on a user's behalf, which is
# the shape of an SSRF. Registered targets that resolve into private, loopback,
# link-local or reserved space are refused by default, so an internet-facing
# instance cannot be pointed at the network behind it.
#
# An installation that lives *inside* the network it watches has the opposite
# problem — everything it should check is private. Then this is switched on
# deliberately, which is a decision someone made rather than a hole.
MONITOR_ALLOW_PRIVATE = os.getenv("MONITOR_ALLOW_PRIVATE", "false").lower() == "true"

# A check waits this long before giving up. Short: an unreachable host is a
# finding, not a reason to hold the request open.
MONITOR_TIMEOUT_SECONDS = float(os.getenv("MONITOR_TIMEOUT_SECONDS", "8"))

# Signs the short-lived session cookie that carries the PKCE code_verifier
# between /auth/login and /callback.
SESSION_SECRET = _required("SESSION_SECRET")

# A Secure cookie is never sent over plain HTTP, which would break the login
# round-trip on a http://localhost redirect URI. Keep this on in production.
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() != "false"

