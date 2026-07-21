import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import (
    OIDC_AUDIENCE,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_ISSUER,
    OIDC_REDIRECT_URI,
    OIDC_SCOPE,
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

_jwks_cache: dict = {"keys": None, "fetched_at": 0.0}
_userinfo_cache: dict = {}


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _load_jwks() -> dict:
    now = time.monotonic()

    if _jwks_cache["keys"] and now - _jwks_cache["fetched_at"] < _JWKS_TTL_SECONDS:
        return _jwks_cache["keys"]

    with httpx.Client(timeout=10) as client:
        response = client.get(f"{OIDC_ISSUER}/.well-known/jwks.json")
        response.raise_for_status()
        keys = response.json()

    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = now

    return keys


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


def _claims_from_jwt(token: str) -> dict:
    try:
        claims = _jwt.decode(token, _load_jwks())
        claims.validate()
    except JoseError as error:
        raise _unauthorized("Invalid token") from error

    if claims.get("iss") != OIDC_ISSUER:
        raise _unauthorized("Invalid token issuer")

    # Some deployments issue access tokens whose audience is an API identifier
    # rather than the client id, so the expected value is configurable. A token
    # that carries an "aud" must always match it.
    audience = claims.get("aud")

    if audience is not None:
        allowed = audience if isinstance(audience, list) else [audience]

        if OIDC_AUDIENCE not in allowed:
            raise _unauthorized("Invalid token audience")

    return dict(claims)


def _claims_from_userinfo(token: str) -> dict:
    cached = _userinfo_cache.get(token)

    if cached and time.monotonic() < cached["expires_at"]:
        return cached["claims"]

    with httpx.Client(timeout=10) as client:
        response = client.get(
            f"{OIDC_ISSUER}/oauth/userinfo",
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


def _upsert_user(db: Session, claims: dict) -> User:
    subject = claims.get("sub")

    if not subject:
        raise _unauthorized("Token is missing the sub claim")

    user = (
        db.query(User)
        .filter(User.oidc_issuer == OIDC_ISSUER, User.oidc_sub == subject)
        .first()
    )

    email = claims.get("email")
    username = claims.get("preferred_username") or claims.get("name") or email or subject

    if user is None:
        user = User(
            oidc_issuer=OIDC_ISSUER,
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
    if _looks_like_jwt(token):
        claims = _claims_from_jwt(token)
    else:
        claims = _claims_from_userinfo(token)

    user = _upsert_user(db, claims)

    # Roles come from the token, not the database, so they always reflect the
    # provider's current grant. Stashed on the instance for require_role; not
    # persisted.
    user.roles = claims.get("roles") or []

    return user


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

_HOSTED_LOGIN_URL = f"{OIDC_ISSUER}/login"


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


@router.get("/login")
def login(request: Request):
    verifier, challenge = _make_pkce()
    request.session["code_verifier"] = verifier

    query = urlencode(
        {
            "response_type": "code",
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "scope": OIDC_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    return RedirectResponse(f"{OIDC_ISSUER}/oauth/authorize?{query}", status_code=302)


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

    # No provider session yet: send the browser to the provider's own login
    # page so the password is entered there, never here.
    if login_session and not code:
        return RedirectResponse(
            f"{_HOSTED_LOGIN_URL}?{urlencode({'login_session': login_session})}",
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
            f"{OIDC_ISSUER}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
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
        claims = _claims_from_jwt(id_token)
    else:
        claims = _claims_from_userinfo(access_token)

    user = _upsert_user(db, claims)

    return {
        "access_token": access_token,
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": token.get("expires_in"),
        "refresh_token": token.get("refresh_token"),
        "id_token": id_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
    }


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email}


@router.get("/logout")
def logout(request: Request):
    request.session.clear()

    return {"logout_url": f"{OIDC_ISSUER}/oauth/logout"}
