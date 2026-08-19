import os
from dataclasses import dataclass


def _required(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(f"{name} environment variable is not set")

    return value


@dataclass(frozen=True)
class Provider:
    """One identity provider this installation will accept a login from.

    Multiple providers are not a convenience feature. A tracker whose only way
    in is a single provider stops being usable the moment that provider has a
    bad day — which is not hypothetical here: an authentication-flow regression
    at the provider left this application unreachable for two weeks.
    """

    key: str
    label: str
    issuer: str
    client_id: str
    client_secret: str
    audience: str
    scope: str
    authorize_url: str
    token_url: str
    jwks_url: str
    userinfo_url: str
    # Not every provider implements RP-initiated logout; Google does not.
    logout_url: str | None = None
    # OpenIDX bounces an unauthenticated browser back with ?login_session=…
    # instead of showing a login page, so its own page has to be addressed
    # directly. Standard providers leave this unset.
    hosted_login_url: str | None = None


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

# --- AI analysis -------------------------------------------------------------
#
# A model reads a finding and says how exploitable it looks, what it would cost,
# and how to fix it. Three decisions are baked in here rather than left to the
# caller, and each one is a refusal:
#
# 1. The endpoint comes from this file, never from a request. A backend that
#    POSTs to a URL the user typed — carrying an API key — is the same SSRF this
#    application already refuses for monitoring, with a credential attached. The
#    interface may display and test the endpoint; it may not set it.
# 2. A self-hosted model is the default. Findings describe what is broken and
#    where, and the code quoted with them can contain the very secret a rule
#    flagged. That is not data to hand to a third party by accident — it has to
#    be a decision.
# 3. Nothing is configured by default. With no provider set the feature is
#    absent rather than broken, and no analysis button appears.
AI_PROVIDER = os.getenv("AI_PROVIDER", "").strip().lower()

# OpenAI-compatible chat completions. Ollama, vLLM and llama.cpp all speak it,
# so "self-hosted" is one setting rather than one integration per runtime.
AI_LOCAL_BASE_URL = os.getenv("AI_LOCAL_BASE_URL", "http://localhost:11434/v1")
AI_LOCAL_MODEL = os.getenv("AI_LOCAL_MODEL", "llama3.1")
# Sent as a bearer token when the local runtime wants one (vLLM often does).
AI_LOCAL_API_KEY = os.getenv("AI_LOCAL_API_KEY", "")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")

# Whether the quoted source may be sent with the finding. Without it the model
# is grading a rule name and its answer is worth about as much; with it, the
# request carries someone's source code. Redaction runs either way — this only
# decides whether the code is in the request at all.
AI_SEND_CODE = os.getenv("AI_SEND_CODE", "true").lower() != "false"

# An analysis is one request to one model. Long enough for a slow local model to
# think, short enough that a hung endpoint does not hold a worker open.
AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", "60"))

# Analyses per user per hour. Not abuse protection so much as bill protection:
# an authenticated user should not be able to spend an afternoon's inference
# budget by holding down a button.
AI_HOURLY_LIMIT = int(os.getenv("AI_HOURLY_LIMIT", "40"))

# --- The providers this installation accepts -------------------------------

OPENIDX = Provider(
    key="openidx",
    label="OpenIDX",
    issuer=OIDC_ISSUER,
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    audience=OIDC_AUDIENCE,
    scope=OIDC_SCOPE,
    authorize_url=f"{OIDC_ISSUER}/oauth/authorize",
    token_url=f"{OIDC_ISSUER}/oauth/token",
    jwks_url=f"{OIDC_ISSUER}/.well-known/jwks.json",
    userinfo_url=f"{OIDC_ISSUER}/oauth/userinfo",
    logout_url=f"{OIDC_ISSUER}/oauth/logout",
    hosted_login_url=f"{OIDC_ISSUER}/login",
)

# Google is a plain OpenID Connect provider: discovery, JWKS, id_token, PKCE.
# It is here as the second way in, and it only appears when credentials for it
# exist — an installation that has not configured it shows one button, not a
# broken one.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

GOOGLE = Provider(
    key="google",
    label="Google",
    issuer="https://accounts.google.com",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    audience=GOOGLE_CLIENT_ID,
    scope="openid email profile",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    jwks_url="https://www.googleapis.com/oauth2/v3/certs",
    userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
    # Google has no RP-initiated logout endpoint; signing out of this
    # application cannot end the Google session, and pretending otherwise
    # would be worse than saying so.
    logout_url=None,
)

PROVIDERS: dict[str, Provider] = {OPENIDX.key: OPENIDX}

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    PROVIDERS[GOOGLE.key] = GOOGLE

# The one a bare /auth/login uses, and the one an opaque (non-JWT) token is
# assumed to have come from.
DEFAULT_PROVIDER = OPENIDX.key

# Signs the short-lived session cookie that carries the PKCE code_verifier
# between /auth/login and /callback.
SESSION_SECRET = _required("SESSION_SECRET")

# A Secure cookie is never sent over plain HTTP, which would break the login
# round-trip on a http://localhost redirect URI. Keep this on in production.
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() != "false"

