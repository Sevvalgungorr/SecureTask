import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import (
    DEFAULT_PROVIDER,
    OIDC_MFA_ACR,
    OIDC_MFA_AMR,
    OIDC_POST_LOGOUT_REDIRECT_URI,
    OIDC_REDIRECT_URI,
    PROVIDERS,
    STEP_UP_REQUIRED,
    Provider,
)
from app.database import get_db
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])

# The callback path must match the redirect_uri registered with the provider
# exactly, which is /callback rather than /auth/callback.
callback_router = APIRouter(tags=["auth"])

# The provider signs with RS256 only. Pinning the accepted algorithms stops a
# forged token from selecting a weaker one (e.g. "none" or an HMAC alg).
_ALLOWED_ALGORITHMS = ["RS256"]
_jwt = JsonWebToken(_ALLOWED_ALGORITHMS)

_JWKS_TTL_SECONDS = 3600
_USERINFO_TTL_SECONDS = 60

# Keyed by provider: two providers have two key sets, and caching them
# together would let one answer for the other.
_jwks_cache: dict[str, dict] = {}
_userinfo_cache: dict = {}


def provider_for(key: str | None) -> Provider:
    """The configured provider named by `key`, or the default."""
    return PROVIDERS.get(key or DEFAULT_PROVIDER) or PROVIDERS[DEFAULT_PROVIDER]


def _unverified_issuer(token: str) -> str | None:
    """Read `iss` out of a JWT without trusting it.

    Only used to decide *which* key set to verify against — the same thing
    issuer-based key discovery does everywhere. The claim is then checked
    again after verification, against the provider it selected, so a forged
    `iss` selects a provider whose keys will not validate the signature.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("iss")
    except (ValueError, IndexError, json.JSONDecodeError):
        return None


def provider_for_token(token: str) -> Provider:
    """Which provider a bearer token claims to be from."""
    issuer = _unverified_issuer(token)

    for candidate in PROVIDERS.values():
        if candidate.issuer == issuer:
            return candidate

    # An opaque token carries no issuer to read; it can only have come from a
    # provider that issues them, which here is the default one.
    return PROVIDERS[DEFAULT_PROVIDER]


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _load_jwks(provider: Provider) -> dict:
    now = time.monotonic()
    cached = _jwks_cache.get(provider.key)

    if cached and now - cached["fetched_at"] < _JWKS_TTL_SECONDS:
        return cached["keys"]

    with httpx.Client(timeout=10) as client:
        response = client.get(provider.jwks_url)
        response.raise_for_status()
        keys = response.json()

    _jwks_cache[provider.key] = {"keys": keys, "fetched_at": now}

    return keys


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


def _claims_from_jwt(token: str, provider: Provider) -> dict:
    try:
        claims = _jwt.decode(token, _load_jwks(provider))
        claims.validate()
    except JoseError as error:
        raise _unauthorized("Invalid token") from error

    # Checked again after verification: the unverified read only chose which
    # keys to try, and a token that verified under one provider's keys must
    # also say it came from that provider.
    if claims.get("iss") != provider.issuer:
        raise _unauthorized("Invalid token issuer")

    # Some deployments issue access tokens whose audience is an API identifier
    # rather than the client id, so the expected value is configurable. A token
    # that carries an "aud" must always match it.
    audience = claims.get("aud")

    if audience is not None:
        allowed = audience if isinstance(audience, list) else [audience]

        if provider.audience not in allowed:
            raise _unauthorized("Invalid token audience")

    return dict(claims)


def _claims_from_userinfo(token: str, provider: Provider) -> dict:
    cached = _userinfo_cache.get(token)

    if cached and time.monotonic() < cached["expires_at"]:
        return cached["claims"]

    with httpx.Client(timeout=10) as client:
        response = client.get(
            provider.userinfo_url,
            headers={"Authorization": f"Bearer {token}"},
        )

    if response.status_code == 401:
        raise _unauthorized("Invalid token")

    response.raise_for_status()
    claims = response.json()

    _userinfo_cache[token] = {
        "claims": claims,
        "expires_at": time.monotonic() + _USERINFO_TTL_SECONDS,
    }

    return claims


def _upsert_user(db: Session, claims: dict, provider: Provider) -> User:
    subject = claims.get("sub")

    if not subject:
        raise _unauthorized("Token is missing the sub claim")

    user = (
        db.query(User)
        .filter(User.oidc_issuer == provider.issuer, User.oidc_sub == subject)
        .first()
    )

    email = claims.get("email")
    username = claims.get("preferred_username") or claims.get("name") or email or subject

    if user is None:
        user = User(
            oidc_issuer=provider.issuer,
            oidc_sub=subject,
            username=username,
            email=email,
        )
        db.add(user)
    else:
        user.username = username
        user.email = email

    db.commit()
    db.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is disabled")

    return user


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _unauthorized("Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise _unauthorized("Missing bearer token")

    # A JWT is verified locally against the provider's JWKS. An opaque token
    # carries no verifiable claims, so the provider itself must vouch for it.
    provider = provider_for_token(token)

    if _looks_like_jwt(token):
        claims = _claims_from_jwt(token, provider)
    else:
        claims = _claims_from_userinfo(token, provider)

    user = _upsert_user(db, claims, provider)
    # Which provider this session came from, for the interface to show and for
    # logout to know whose session to end.
    user.provider = provider.key

    # Roles come from the token, not the database, so they always reflect the
    # provider's current grant. Stashed on the instance for require_role; not
    # persisted.
    user.roles = claims.get("roles") or []

    # How this session authenticated, for step-up decisions. Same reasoning as
    # roles: it describes the token, so it is read from the token every time
    # rather than remembered against the user row.
    amr = claims.get("amr")
    user.amr = amr if isinstance(amr, list) else ([amr] if amr else [])
    user.acr = claims.get("acr")

    return user


def has_mfa(user: User) -> bool:
    """Whether the token says this session cleared a second factor."""
    amr = {str(m).lower() for m in getattr(user, "amr", []) or []}
    acr = getattr(user, "acr", None)

    if amr & OIDC_MFA_AMR:
        return True

    return bool(acr) and str(acr).lower() in OIDC_MFA_ACR


def require_step_up(user: User) -> None:
    """Guard the actions that decide to live with a risk.

    Deliberately fail-closed: a token that carries no `amr`/`acr` is treated as
    single-factor. If the provider does not emit either claim the action stays
    blocked, which is the safe way to be wrong — and the operator can set
    OIDC_MFA_AMR/OIDC_MFA_ACR to the values it does emit, or turn the check off
    with STEP_UP_REQUIRED=false, both of which are explicit choices.
    """
    if not STEP_UP_REQUIRED or has_mfa(user):
        return

    raise HTTPException(
        status_code=403,
        detail=(
            "Bir riski kabul etmek çok faktörlü doğrulama gerektirir. "
            "Çıkış yapıp MFA ile yeniden giriş yapın."
        ),
    )


def require_role(role: str):
    """Dependency factory: allow only users whose token carries `role`."""

    def dependency(user: User = Depends(get_current_user)) -> User:
        if role not in getattr(user, "roles", []):
            raise HTTPException(
                status_code=403,
                detail=f"This action requires the '{role}' role",
            )

        return user

    return dependency


# --- Interactive login (redirect / SSO) -----------------------------------
#
# The provider does not host a login page at a well-known URL nor implement the
# OAuth `state` parameter. Its authorization endpoint bounces an unauthenticated
# browser back to the redirect_uri with `?login_session=X`; the provider's OWN
# login page lives at /login and reads that login_session. So we keep the
# password on the provider: bounce the browser there and let it come back with
# a code. The flow, all via browser redirects:
#
#   1. /auth/login  -> generate PKCE, store verifier in the session cookie,
#                      redirect to /oauth/authorize
#   2. provider     -> /callback?login_session=X   (user has no session yet)
#   3. /callback    -> redirect to /login?login_session=X   (provider-hosted UI)
#   4. user signs in on the provider, which redirects to /callback?code=Y
#   5. /callback    -> exchange code + stored verifier for tokens
#
# PKCE (S256) is the interception defence; there is no state/nonce because the
# provider supports neither. The verifier lives only in our signed session
# cookie, which also ties the callback to the browser that started the login.

def _make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return verifier, challenge


def _param_from_url(url: str, name: str) -> str | None:
    if not url:
        return None

    values = parse_qs(urlparse(url).query).get(name)

    return values[0] if values else None


@router.get("/providers")
def providers():
    """Which ways in this installation offers.

    The interface asks rather than assuming, so adding a provider is a matter
    of configuration and not of editing the login page.
    """
    return [
        {"key": p.key, "label": p.label} for p in PROVIDERS.values()
    ]


@router.get("/login")
def login(request: Request, provider: str | None = None):
    if provider is not None and provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Böyle bir sağlayıcı yok")

    chosen = provider_for(provider)
    verifier, challenge = _make_pkce()
    request.session["code_verifier"] = verifier
    # The callback has to verify against the same provider the login started
    # at, and the browser must not get to choose which one that was.
    request.session["provider"] = chosen.key

    query = urlencode(
        {
            "response_type": "code",
            "client_id": chosen.client_id,
            "redirect_uri": OIDC_REDIRECT_URI,
            "scope": chosen.scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    return RedirectResponse(f"{chosen.authorize_url}?{query}", status_code=302)


@callback_router.get("/callback")
def callback(request: Request, db: Session = Depends(get_db)):
    login_session = request.query_params.get("login_session")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        raise HTTPException(
            status_code=401,
            detail=request.query_params.get("error_description") or error,
        )

    # Which provider this login started at. Read from our own signed session,
    # never from the query string: letting the browser name the provider would
    # let it point the code exchange at one of its choosing.
    chosen = provider_for(request.session.get("provider"))

    # No provider session yet: send the browser to the provider's own login
    # page so the password is entered there, never here. Only OpenIDX takes
    # this branch; a standard provider shows its own page and never bounces
    # back with a login_session.
    if login_session and not code and chosen.hosted_login_url:
        return RedirectResponse(
            f"{chosen.hosted_login_url}?{urlencode({'login_session': login_session})}",
            status_code=302,
        )

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    verifier = request.session.pop("code_verifier", None)

    if not verifier:
        raise HTTPException(
            status_code=400,
            detail="No login in progress; start again at /auth/login",
        )

    with httpx.Client(timeout=15) as client:
        response = client.post(
            chosen.token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": chosen.client_id,
                "client_secret": chosen.client_secret,
                "code": code,
                "redirect_uri": OIDC_REDIRECT_URI,
                "code_verifier": verifier,
            },
        )

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Token exchange failed")

    token = response.json()
    access_token = token.get("access_token")
    id_token = token.get("id_token")

    if not access_token:
        raise HTTPException(status_code=502, detail="No access token returned")

    # Prefer the id_token for identity claims: its signature is verified against
    # the JWKS. Fall back to the userinfo endpoint if none was issued.
    if id_token:
        claims = _claims_from_jwt(id_token, chosen)
    else:
        claims = _claims_from_userinfo(access_token, chosen)

    _upsert_user(db, claims, chosen)

    # Keep the id_token server-side, in the signed session cookie: logout needs it
    # as the id_token_hint, and the browser never has to hold a second credential.
    if id_token:
        request.session["id_token"] = id_token

    # Hand the browser the credential this application can actually verify.
    #
    # Every request is authorised by verifying a JWT against its issuer's JWKS,
    # which needs a token that carries `iss` and a signature. Whether the access
    # token is such a thing is up to the provider: OpenIDX issues a JWT, Google
    # issues an opaque string (`ya29…`) that means nothing outside Google.
    #
    # Handing over an opaque token looked fine until a second provider was real.
    # It has no `iss` to read, so it fell back to the default provider and was
    # checked against the wrong keys — login succeeded, the account was created,
    # and every request after it came back 401. The id_token is the one the
    # standard guarantees to be a signed JWT naming its issuer, so that is what
    # goes when the access token cannot be verified here.
    bearer = access_token if _looks_like_jwt(access_token) else id_token

    if not bearer:
        # An opaque access token and no id_token: nothing here can be checked
        # on later requests, and issuing a credential this application cannot
        # verify would mean trusting whatever comes back holding it.
        raise HTTPException(
            status_code=502,
            detail="Sağlayıcı doğrulanabilir bir token vermedi.",
        )

    # (json.dumps safely quotes the token for embedding in the script.)
    #
    # This is the application's only inline script, and it stays inline on
    # purpose: the alternative is putting the token in the URL, where it would
    # land in browser history. It carries the response's CSP nonce, so the
    # policy admits this one script by name rather than admitting all of them.
    nonce = request.state.csp_nonce
    handoff = (
        '<!doctype html><meta charset="utf-8">'
        f'<script nonce="{nonce}">'
        f"localStorage.setItem('securetask_token', {json.dumps(bearer)});"
        "location.replace('/app');"
        "</script>Giriş yapılıyor…"
    )
    return HTMLResponse(handoff)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": getattr(user, "roles", []),
        # Surfaced so the interface can say up front whether this session may
        # accept a risk, instead of only finding out when the action is refused.
        "amr": getattr(user, "amr", []),
        "acr": getattr(user, "acr", None),
        "mfa": has_mfa(user),
        "step_up_required": STEP_UP_REQUIRED,
        "provider": getattr(user, "provider", None),
    }


@router.get("/logout")
def logout(request: Request):
    """Build the provider's RP-initiated logout URL and drop the local session.

    Clearing our own token only signs the user out of this app; the provider's
    SSO session stays open and the next login is granted silently. Sending the
    browser to the end_session endpoint ends that session too, so signing out
    means signing out.
    """
    # Read the hint and the provider before clearing: the session is where
    # both live.
    id_token = request.session.get("id_token")
    chosen = provider_for(request.session.get("provider"))
    request.session.clear()

    # Not every provider offers RP-initiated logout — Google does not. Saying
    # so is better than sending the browser somewhere that will not end the
    # session and calling it a sign-out.
    if not chosen.logout_url:
        return {
            "logout_url": None,
            "provider": chosen.key,
            "note": (
                f"{chosen.label} oturum sonlandırma ucu sunmuyor; yalnızca bu "
                "uygulamadaki oturum kapatıldı."
            ),
        }

    params = {}

    # Tells the provider which session to end. Without it some providers fall
    # back to asking the user which account to sign out of.
    if id_token:
        params["id_token_hint"] = id_token

    if OIDC_POST_LOGOUT_REDIRECT_URI:
        params["post_logout_redirect_uri"] = OIDC_POST_LOGOUT_REDIRECT_URI

    logout_url = chosen.logout_url

    if params:
        logout_url = f"{logout_url}?{urlencode(params)}"

    return {"logout_url": logout_url, "provider": chosen.key}
