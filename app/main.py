import secrets
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app import ai, audit
from app.auth import (
    callback_router,
    get_current_user,
    has_mfa,
    require_role,
    require_step_up,
    router as auth_router,
)
from app.config import AI_HOURLY_LIMIT, SESSION_HTTPS_ONLY, SESSION_SECRET
from app.database import SessionLocal, engine, get_db
from app.importers import parse_nuclei, parse_sarif
from app.monitor import TargetRefused, assert_target_allowed, run_checks
from app.source import SourceUnavailable, window_for
from app.models import (
    ACCEPTED_RISK,
    MAX_ACCEPTANCE_DAYS,
    MIN_ACCEPTANCE_REASON,
    SEVERITY_ORDER,
    SLA_DAYS,
    TEAM_RISK_OWNER,
    AIAnalysis,
    Asset,
    AuditLog,
    Finding,
    Team,
    TeamMember,
    User,
)
from app.schemas import (
    AIAnalysisResponse,
    AIProviderResponse,
    AssetCreate,
    AssetResponse,
    AssigneeUpdate,
    AuditLogResponse,
    FindingCreate,
    FindingResponse,
    FindingUpdate,
    TeamCreate,
    TeamMemberAdd,
    TeamResponse,
)

app = FastAPI(
    title="SecureTask",
    description=(
        "OpenID Connect ile korunan güvenlik bulgusu takip API'si: ekipler, "
        "bulgular, kritiklik, SLA ve denetlenebilir durum değişiklikleri. "
        "Bir bulgunun riskini yalnızca ekibin risk sahibi kabul edebilir ve "
        "o kişi bulguyu bildiren olamaz."
    ),
    version="2.1.0",
    # The stock docs page pulls Swagger UI from a public CDN, which this
    # application's own Content-Security-Policy forbids — so it rendered blank.
    # Replaced below with the same page served from our own files.
    docs_url=None,
)

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/docs", include_in_schema=False)
def swagger_ui(request: Request):
    """The API docs, served without reaching off this host.

    Vendoring the assets rather than allowing the CDN in the CSP keeps the
    exception from existing at all: a third-party script host that can serve
    anything it likes, on a page that renders the whole API surface, is the
    supply-chain risk this application exists to track. It also means the docs
    work on a machine with no internet access, which is where an internal tool
    usually lives.
    """
    # Written out here rather than through get_swagger_ui_html, which emits an
    # inline <script> with no way to put a nonce on it. Under a policy without
    # 'unsafe-inline' that script is blocked and the page renders blank — which
    # is exactly what happened, and what the earlier test missed by checking
    # that the page was *returned* rather than that it *worked*.
    nonce = request.state.csp_nonce

    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{app.title} — API</title>
<link rel="stylesheet" href="/static/vendor/swagger-ui.css">
<link rel="icon" href="/static/vendor/favicon.svg">
</head>
<body>
<div id="swagger-ui"></div>
<script src="/static/vendor/swagger-ui-bundle.js"></script>
<script nonce="{nonce}">
SwaggerUIBundle({{
  url: "{app.openapi_url}",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis],
  layout: "BaseLayout",
  deepLinking: true,
}});
</script>
</body>
</html>""")


# Holds the PKCE code_verifier between /auth/login and /callback, and ties the
# callback to the browser that began the login. Short-lived; cleared on logout.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=SESSION_HTTPS_ONLY,
    max_age=600,
)

app.include_router(auth_router)
app.include_router(callback_router)


# Adds a few standard security headers to every response — a small, safe
# hardening step that costs nothing and breaks nothing.
@app.middleware("http")
async def security_headers(request, call_next):
    # A fresh nonce per response. The interface itself needs none — its script
    # and styles are files now — but the callback has one unavoidable inline
    # script, and a nonce lets exactly that one run without reopening the door
    # for every other inline script an injection might introduce.
    request.state.csp_nonce = secrets.token_urlsafe(16)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HSTS: tarayıcıya "bu siteye hep HTTPS ile gel" der (MITM/downgrade koruması).
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Permissions-Policy: uygulamanın hiç kullanmadığı güçlü tarayıcı
    # yeteneklerini (konum/mikrofon/kamera) kapatır.
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # CSP: içeriğin nereden yüklenebileceğini kısıtlar. 'unsafe-inline' yok —
    # onunla birlikte başlık, korumak için var olduğu saldırının (enjekte edilen
    # satır içi script) tam olarak önünü açık bırakıyordu. Arayüzün betikleri ve
    # biçemleri artık ayrı dosyalarda; geriye kalan tek satır içi script
    # (/callback'in token devri) nonce ile adlandırılarak çalışıyor.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{request.state.csp_nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


# Basit bellek-içi istek sınırlama (rate limit): her IP için pencere başına
# en fazla _RATE_LIMIT istek — temel bir brute-force / kötüye kullanım koruması.
_RATE_LIMIT = 60
_RATE_WINDOW = 60
_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request, call_next):
    client = request.client.host if request.client else "unknown"
    now = time.time()
    hits = _hits[client]

    # Pencereden çıkmış (eski) istekleri unut
    while hits and hits[0] <= now - _RATE_WINDOW:
        hits.popleft()

    if len(hits) >= _RATE_LIMIT:
        return JSONResponse(
            status_code=429, content={"detail": "Too many requests"}
        )

    hits.append(now)
    return await call_next(request)


def _sanitize_log(text: str) -> str:
    # Strip CR/LF so user-supplied values can't forge extra log lines
    # (CWE-117 log injection) — same guard OpenIDX applies to its audit log.
    return text.replace("\r", "").replace("\n", "")


# Records every denied request (401 unauthenticated, 403 forbidden) to the
# audit log — a lightweight security-event trail of who tried to reach what.
@app.middleware("http")
async def log_denied_access(request, call_next):
    response = await call_next(request)

    if response.status_code in (401, 403):
        detail = _sanitize_log(
            f"{response.status_code} {request.method} {request.url.path}"
        )
        db = SessionLocal()
        try:
            audit.append(db, action="access_denied", detail=detail)
            db.commit()
        finally:
            db.close()

    return response


def _record_audit(
    db: Session,
    user: User,
    action: str,
    finding_id: int,
    detail: str | None = None,
) -> None:
    audit.append(
        db, user_id=user.id, action=action, finding_id=finding_id, detail=detail
    )
    db.commit()


def _my_team_ids(db: Session, user: User) -> list[int]:
    return [
        row.team_id
        for row in db.query(TeamMember).filter(TeamMember.user_id == user.id).all()
    ]


def _my_role_in(db: Session, user: User, team_id: int) -> str | None:
    """The caller's role in one team, or None if they are not in it."""
    membership = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id, TeamMember.user_id == user.id)
        .first()
    )

    return membership.role if membership else None


def _visible_to(db: Session, user: User):
    """The findings this user may see: their own, plus their teams'.

    A finding with no team stays private to whoever filed it, which is what
    every row looked like before teams existed.
    """
    team_ids = _my_team_ids(db, user)

    return or_(Finding.owner_id == user.id, Finding.team_id.in_(team_ids))


def _get_visible_finding(finding_id: int, user: User, db: Session) -> Finding:
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, _visible_to(db, user))
        .first()
    )

    # A finding belonging to someone else's team is reported as missing rather
    # than forbidden, so the endpoint does not confirm that the id exists.
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


def _require_membership(db: Session, user: User, team_id: int) -> str:
    """Refuse a team the caller is not in, without confirming it exists."""
    role = _my_role_in(db, user, team_id)

    if role is None:
        raise HTTPException(status_code=404, detail="Ekip bulunamadı")

    return role


def _assert_may_accept(db: Session, user: User, finding: Finding) -> None:
    """Separation of duties: the one who reports may not be the one who accepts.

    Accepting a risk is the only way to close a finding while leaving the
    problem in place, so it is the decision most worth splitting between two
    people. Whoever filed it has already said it matters; letting the same
    person then declare it acceptable makes the record of that decision worth
    nothing.

    A finding with no team is outside this rule — not as an exception granted,
    but because one person cannot be two, and a personal list has no second
    person to ask. That the separation did not apply is written into the log.
    """
    if finding.team_id is None:
        return

    if _my_role_in(db, user, finding.team_id) != TEAM_RISK_OWNER:
        raise HTTPException(
            status_code=403,
            detail="Bir riski yalnızca ekibin risk sahibi kabul edebilir.",
        )

    if finding.owner_id == user.id:
        raise HTTPException(
            status_code=403,
            detail=(
                "Kendi bildirdiğin bulgunun riskini kabul edemezsin — "
                "kabulü ekipteki başka bir risk sahibi vermeli (görev ayrılığı)."
            ),
        )


def _sla_due_date(severity: str) -> date:
    """The remediation deadline implied by a severity, counted from today."""
    return date.today() + timedelta(days=SLA_DAYS[severity])


def _validate_acceptance(data: FindingCreate) -> None:
    """A risk may only be accepted with an argument and an end date.

    Both are refused rather than defaulted. A default reason would be no reason,
    and a default expiry would decide on someone's behalf how long the
    organisation carries this — which is the decision being made.
    """
    reason = (data.accepted_reason or "").strip()

    if len(reason) < MIN_ACCEPTANCE_REASON:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Riski kabul etmek için gerekçe yazılmalı "
                f"(en az {MIN_ACCEPTANCE_REASON} karakter)."
            ),
        )

    if data.accepted_until is None:
        raise HTTPException(
            status_code=422,
            detail="Riski kabul etmek için bir bitiş tarihi verilmeli.",
        )

    today = date.today()

    if data.accepted_until <= today:
        raise HTTPException(
            status_code=422, detail="Bitiş tarihi gelecekte olmalı."
        )

    if (data.accepted_until - today).days > MAX_ACCEPTANCE_DAYS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Bir risk en fazla {MAX_ACCEPTANCE_DAYS} gün için kabul "
                "edilebilir. Süresi dolunca bulgu yeniden açılır."
            ),
        )


def _apply_acceptance(finding: Finding, data: FindingCreate, user: User) -> None:
    finding.accepted_reason = (data.accepted_reason or "").strip()
    finding.accepted_until = data.accepted_until
    finding.accepted_at = datetime.now(timezone.utc)
    finding.accepted_by_id = user.id


def _clear_acceptance(finding: Finding) -> None:
    """Drop the acceptance when it ends.

    The fields describe the acceptance in force; once it is over they would
    only mislead. What was accepted, by whom and until when stays in the audit
    log, which is the record that is meant to be read back.
    """
    finding.accepted_reason = None
    finding.accepted_until = None
    finding.accepted_at = None
    finding.accepted_by_id = None


def _describe_changes(finding: Finding, new: FindingUpdate, user: User) -> str:
    """Summarise an edit for the audit log.

    Severity and status are spelled out because those two carry the risk
    decision: downgrading a critical finding, or closing one as accepted risk,
    must be readable in the log afterwards without diffing the row.
    """
    changes = [
        f"{field} {before}→{after}"
        for field, before, after in (
            ("severity", finding.severity, new.severity),
            ("status", finding.status, new.status),
        )
        if before != after
    ]

    # Record that the second factor was actually presented, not just that the
    # risk was accepted — otherwise the log cannot show the guard held.
    if new.status == ACCEPTED_RISK and finding.status != ACCEPTED_RISK and has_mfa(user):
        changes.append("mfa doğrulandı")

    return " · ".join([new.title, *changes])


_FRONTEND = _STATIC / "index.html"


@app.get("/")
def root():
    return {"message": "SecureTask API"}


@app.get("/app", response_class=HTMLResponse)
def frontend():
    return _FRONTEND.read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db-health")
def database_health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

    return {"database": "connected"}


@app.post("/findings", response_model=FindingResponse)
def create_finding(
    finding: FindingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if finding.team_id is not None:
        _require_membership(db, user, finding.team_id)

    new_finding = Finding(
        title=finding.title,
        description=finding.description,
        asset=finding.asset,
        severity=finding.severity,
        status=finding.status,
        due_date=finding.due_date or _sla_due_date(finding.severity),
        owner_id=user.id,
        team_id=finding.team_id,
    )

    # Filing a finding as already-accepted is the same decision as accepting one
    # later, so it meets the same bar. Inside a team it can never be met on the
    # way in: the reporter is the caller, and the reporter may not accept.
    if finding.status == ACCEPTED_RISK:
        require_step_up(user)
        _assert_may_accept(db, user, new_finding)
        _validate_acceptance(finding)
        _apply_acceptance(new_finding, finding, user)

    db.add(new_finding)
    db.commit()
    db.refresh(new_finding)

    _record_audit(
        db,
        user,
        "created",
        new_finding.id,
        f"{new_finding.title} · severity {new_finding.severity}",
    )

    return new_finding


@app.get("/findings", response_model=list[FindingResponse])
def get_findings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Finding).filter(_visible_to(db, user)).all()


@app.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_visible_finding(finding_id, user, db)


@app.put("/findings/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    finding_data: FindingUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _get_visible_finding(finding_id, user, db)

    # Which team a finding belongs to says who may see it, so it is not part of
    # an ordinary edit. Changing it silently through a full-row update would
    # move a finding out of sight of the people working it.
    if finding_data.team_id != finding.team_id:
        raise HTTPException(
            status_code=422,
            detail="Bir bulgunun ekibi güncelleme ile değiştirilemez.",
        )

    # Only the transition is guarded. A finding that is already accepted can
    # still be retitled or re-described without a second factor; what needs one
    # is the decision to carry the risk.
    if finding_data.status == ACCEPTED_RISK and finding.status != ACCEPTED_RISK:
        require_step_up(user)
        _assert_may_accept(db, user, finding)
        _validate_acceptance(finding_data)

    # Read the change summary before the row is overwritten.
    detail = _describe_changes(finding, finding_data, user)

    finding.title = finding_data.title
    finding.description = finding_data.description
    finding.asset = finding_data.asset
    was_accepted = finding.status == ACCEPTED_RISK
    finding.severity = finding_data.severity
    finding.status = finding_data.status
    finding.due_date = finding_data.due_date

    if finding_data.status == ACCEPTED_RISK and not was_accepted:
        _apply_acceptance(finding, finding_data, user)
    elif finding_data.status != ACCEPTED_RISK and was_accepted:
        # Leaving the accepted state ends the acceptance, whatever it moved to.
        _clear_acceptance(finding)

    db.commit()
    db.refresh(finding)

    _record_audit(db, user, "updated", finding.id, detail)

    return finding


@app.delete("/findings/{finding_id}")
def delete_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _get_visible_finding(finding_id, user, db)

    # Deleting is the one action a team-mate cannot take on someone else's
    # behalf: it removes the row rather than recording an outcome for it. The
    # reporter may withdraw what they filed, and a risk owner may clear the
    # board; anyone else has "fixed" and "accepted" to work with.
    if finding.team_id is not None and finding.owner_id != user.id:
        if _my_role_in(db, user, finding.team_id) != TEAM_RISK_OWNER:
            raise HTTPException(
                status_code=403,
                detail="Bu bulguyu yalnızca bildiren kişi veya ekibin risk sahibi silebilir.",
            )

    title = finding.title

    db.delete(finding)
    db.commit()

    _record_audit(db, user, "deleted", finding_id, title)

    return {"message": "Finding deleted"}


@app.put("/findings/{finding_id}/assignee", response_model=FindingResponse)
def set_assignee(
    finding_id: int,
    data: AssigneeUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Hand a finding to someone, or hand it back.

    Its own endpoint rather than a field on the full-row update: assignment is
    a statement about a person, and it should not be possible to reassign
    someone's work as a side effect of fixing a typo in the title.
    """
    finding = _get_visible_finding(finding_id, user, db)

    if finding.team_id is None:
        raise HTTPException(
            status_code=422,
            detail="Kişisel bir bulgu atanamaz — önce bir ekibe ait olmalı.",
        )

    if data.assignee_id is None:
        finding.assignee_id = None
        db.commit()
        db.refresh(finding)
        _record_audit(db, user, "assigned", finding.id,
                      f"{finding.title} · atama kaldırıldı")

        return finding

    # Assigning outside the team would put work on someone who cannot see it.
    assignee = (
        db.query(User)
        .join(TeamMember, TeamMember.user_id == User.id)
        .filter(User.id == data.assignee_id, TeamMember.team_id == finding.team_id)
        .first()
    )

    if assignee is None:
        raise HTTPException(
            status_code=422, detail="Atanan kişi bu ekibin üyesi değil."
        )

    finding.assignee_id = assignee.id
    db.commit()
    db.refresh(finding)

    _record_audit(db, user, "assigned", finding.id,
                  f"{finding.title} · atandı: {assignee.username}")

    return finding


# --- Teams: the second person in the room ----------------------------------


def _team_response(db: Session, team: Team, my_role: str) -> dict:
    members = (
        db.query(TeamMember, User)
        .join(User, User.id == TeamMember.user_id)
        .filter(TeamMember.team_id == team.id)
        .all()
    )

    return {
        "id": team.id,
        "name": team.name,
        "my_role": my_role,
        "members": [
            {"user_id": user.id, "username": user.username, "role": membership.role}
            for membership, user in members
        ],
    }


@app.post("/teams", response_model=TeamResponse)
def create_team(
    data: TeamCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a team; whoever creates it is its first risk owner.

    Someone has to be able to accept a risk or the team could never close one
    that way — but this does not weaken the separation, because a risk owner
    still cannot accept a finding they reported themselves. A team of one can
    file and fix; to accept, it needs a second person.
    """
    name = data.name.strip()

    if not name:
        raise HTTPException(status_code=422, detail="Ekibin bir adı olmalı.")

    if db.query(Team).filter(Team.name == name).first() is not None:
        raise HTTPException(status_code=409, detail="Bu adda bir ekip zaten var.")

    team = Team(name=name, created_by_id=user.id)
    db.add(team)
    db.flush()

    db.add(TeamMember(team_id=team.id, user_id=user.id, role=TEAM_RISK_OWNER))
    audit.append(
        db, user_id=user.id, action="team_created",
        detail=_sanitize_log(f"ekip oluşturuldu: {name}"),
    )
    db.commit()
    db.refresh(team)

    return _team_response(db, team, TEAM_RISK_OWNER)


@app.get("/teams", response_model=list[TeamResponse])
def list_teams(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The teams the caller belongs to, with who else is in them."""
    rows = (
        db.query(Team, TeamMember)
        .join(TeamMember, TeamMember.team_id == Team.id)
        .filter(TeamMember.user_id == user.id)
        .order_by(Team.name)
        .all()
    )

    return [_team_response(db, team, membership.role) for team, membership in rows]


@app.post("/teams/{team_id}/members", response_model=TeamResponse)
def add_team_member(
    team_id: int,
    data: TeamMemberAdd,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _require_membership(db, user, team_id) != TEAM_RISK_OWNER:
        raise HTTPException(
            status_code=403, detail="Ekibe yalnızca risk sahibi üye ekleyebilir."
        )

    if data.user_id is not None:
        person = db.query(User).filter(User.id == data.user_id).first()
    elif data.email:
        person = (
            db.query(User).filter(User.email == data.email.strip().lower()).first()
        )
    else:
        raise HTTPException(
            status_code=422, detail="Eklenecek kişinin e-postası veya id'si gerekli."
        )

    if person is None:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    existing = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id, TeamMember.user_id == person.id)
        .first()
    )

    if existing is not None:
        # Changing an existing member's role is the same request in practice,
        # and refusing it would only mean remove-then-add.
        existing.role = data.role
    else:
        db.add(TeamMember(team_id=team_id, user_id=person.id, role=data.role))

    audit.append(
        db, user_id=user.id, action="member_added",
        detail=_sanitize_log(f"{person.username} → {data.role} (ekip {team_id})"),
    )
    db.commit()

    team = db.query(Team).filter(Team.id == team_id).first()

    return _team_response(db, team, TEAM_RISK_OWNER)


@app.delete("/teams/{team_id}/members/{user_id}")
def remove_team_member(
    team_id: int,
    user_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _require_membership(db, user, team_id) != TEAM_RISK_OWNER:
        raise HTTPException(
            status_code=403, detail="Ekipten yalnızca risk sahibi üye çıkarabilir."
        )

    membership = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id, TeamMember.user_id == user_id)
        .first()
    )

    if membership is None:
        raise HTTPException(status_code=404, detail="Üye bulunamadı")

    # A team with no risk owner can never accept a risk again, and its open
    # acceptances would expire with nobody able to renew them.
    if membership.role == TEAM_RISK_OWNER:
        remaining = (
            db.query(TeamMember)
            .filter(
                TeamMember.team_id == team_id,
                TeamMember.role == TEAM_RISK_OWNER,
                TeamMember.user_id != user_id,
            )
            .count()
        )

        if remaining == 0:
            raise HTTPException(
                status_code=422,
                detail="Ekibin son risk sahibi çıkarılamaz — önce başka birini risk sahibi yap.",
            )

    db.delete(membership)
    audit.append(
        db, user_id=user.id, action="member_removed",
        detail=_sanitize_log(f"kullanıcı {user_id} ekip {team_id} dışına alındı"),
    )
    db.commit()

    return {"message": "Member removed"}


def _scope(user: User, team_id: int | None):
    """Where a tool's findings live, and what it deduplicates against.

    Filed into a team, a scan result belongs to the team rather than to
    whoever happened to run the scan: two people importing the same output
    should not produce two copies of the same finding.
    """
    if team_id is None:
        return Finding.owner_id == user.id

    return Finding.team_id == team_id


def _ingest(
    db: Session,
    user: User,
    team_id: int | None,
    results: list,
    tool: str,
    skipped: int,
) -> dict:
    """Fold a scan's results into findings, whichever tool produced them.

    Shared by every importer, because the rules are about what a report may do
    to a decision — not about who wrote the report:

    * a finding closed as **fixed** that the tool still sees is **reopened** —
      the evidence says it was not fixed;
    * a finding whose risk was **accepted** is left exactly as it is. Seeing it
      again is the expected outcome of that decision, not news, and an import
      must not quietly undo a decision that required a second factor and a
      second person;
    * an already-open finding keeps its severity unless the *tool's own* rating
      has risen. Someone who triaged a high down to low is not overruled by a
      scanner repeating itself.
    """
    created = reopened = escalated = unchanged = kept_accepted = 0

    for result in results:
        existing = (
            db.query(Finding)
            .filter(
                _scope(user, team_id),
                Finding.asset == result.asset,
                Finding.source_ref == result.source_ref,
            )
            .first()
        )

        if existing is None:
            finding = Finding(
                title=result.title,
                description=result.description,
                asset=result.asset,
                severity=result.severity,
                status="open",
                due_date=_sla_due_date(result.severity),
                source=tool,
                source_ref=result.source_ref,
                source_severity=result.severity,
                evidence=result.evidence or None,
                evidence_start=result.evidence_start,
                evidence_line=result.evidence_line,
                owner_id=user.id,
                team_id=team_id,
            )
            db.add(finding)
            db.flush()  # need the id for the audit entry
            _record_audit(
                db,
                user,
                "created",
                finding.id,
                f"{finding.title} · severity {finding.severity} · {tool} ile içe aktarıldı",
            )
            created += 1
        elif existing.status == ACCEPTED_RISK:
            kept_accepted += 1
        else:
            # The code moves; the snippet from the newest report is the one
            # worth showing. Severity is a judgement and stays put, but the
            # quoted lines are just the current evidence.
            if result.evidence:
                existing.evidence = result.evidence
                existing.evidence_start = result.evidence_start
                existing.evidence_line = result.evidence_line

            escalated_from = _escalate_from_source(existing, result.severity)

            if existing.status == "fixed":
                existing.status = "open"
                # A finding that came back needs a fresh deadline; keeping the
                # old one would file it as overdue the moment it reopens.
                existing.due_date = _sla_due_date(existing.severity)
                _record_audit(
                    db, user, "updated", existing.id,
                    f"{existing.title} · status fixed→open · tarama hâlâ görüyor",
                )
                reopened += 1
            elif escalated_from is not None:
                existing.due_date = _sla_due_date(existing.severity)
                _record_audit(
                    db, user, "updated", existing.id,
                    f"{existing.title} · severity {escalated_from}→{existing.severity} · {tool}",
                )
                escalated += 1
            else:
                unchanged += 1

    summary = (
        f"{tool}: {created} yeni · {reopened} yeniden açıldı · {escalated} yükseltildi "
        f"· {unchanged} değişmedi · {kept_accepted} risk kabul (korundu) "
        f"· {skipped} okunamadı"
    )
    # finding_id is None: this entry is about the import, not one finding.
    audit.append(db, user_id=user.id, action="imported", detail=_sanitize_log(summary))
    db.commit()

    return {
        "tool": tool,
        "created": created,
        "reopened": reopened,
        "escalated": escalated,
        "unchanged": unchanged,
        "kept_accepted": kept_accepted,
        "skipped": skipped,
    }


@app.post("/import/nuclei")
async def import_nuclei(
    request: Request,
    team_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest a nuclei scan (JSON array or one object per line)."""
    if team_id is not None:
        _require_membership(db, user, team_id)

    raw = (await request.body()).decode("utf-8", errors="replace")
    results, skipped = parse_nuclei(raw)

    if not results and not skipped:
        raise HTTPException(status_code=400, detail="Okunabilir tarama sonucu yok")

    return _ingest(db, user, team_id, results, "nuclei", skipped)


@app.post("/import/sarif")
async def import_sarif(
    request: Request,
    team_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest a code-scanning report in SARIF.

    Semgrep, Bandit, CodeQL, gitleaks and GitHub code scanning all emit SARIF,
    so one reader covers the category. The scan itself runs where the code
    already is — a developer's machine or their pipeline — and only the report
    is sent here. Cloning a repository to scan it would mean executing
    untrusted code and holding someone else's source; the tracker has no
    reason to take that on, and every serious tool in this space works the
    same way.
    """
    if team_id is not None:
        _require_membership(db, user, team_id)

    raw = (await request.body()).decode("utf-8", errors="replace")
    results, skipped, tool = parse_sarif(raw)

    if not results and not skipped:
        raise HTTPException(
            status_code=400, detail="Okunabilir SARIF sonucu yok"
        )

    return _ingest(db, user, team_id, results, tool, skipped)


# --- Monitoring: registered assets, and the checks run against them --------


@app.post("/assets", response_model=AssetResponse)
def create_asset(
    asset: AssetCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    host = asset.host.strip().lower()

    # A scheme or a path would mean the value carries more than a host, and the
    # checks only ever address a host.
    if not host or "/" in host or "://" in host or " " in host:
        raise HTTPException(
            status_code=422,
            detail="Yalnızca ana bilgisayar adı girin (şema ve yol olmadan)",
        )

    # Refuse at registration as well as at run time. Rejecting only later would
    # leave a list of targets that look accepted and silently never run.
    try:
        assert_target_allowed(host)
    except TargetRefused as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    existing = (
        db.query(Asset)
        .filter(Asset.owner_id == user.id, Asset.host == host)
        .first()
    )

    if existing is not None:
        raise HTTPException(status_code=409, detail="Bu varlık zaten kayıtlı")

    new_asset = Asset(host=host, label=asset.label.strip(), owner_id=user.id)
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    return new_asset


@app.get("/assets", response_model=list[AssetResponse])
def list_assets(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Asset).filter(Asset.owner_id == user.id).all()


@app.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.owner_id == user.id)
        .first()
    )

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.delete(asset)
    db.commit()

    return {"message": "Asset deleted"}


def _escalate_from_source(finding: Finding, reported: str) -> str | None:
    """Raise a finding's severity when the *tool's own* rating went up.

    Compared against what the source said last time, not against the finding's
    current severity. A tool repeating itself is not new information, so a
    person who lowered this stays lowered; a tool that has started saying
    something worse — a certificate with two days left rather than twenty-eight
    — is reporting a different fact, and that outranks the earlier judgement.
    """
    previous = finding.source_severity or finding.severity
    finding.source_severity = reported

    if SEVERITY_ORDER[reported] <= SEVERITY_ORDER[previous]:
        return None

    if SEVERITY_ORDER[reported] <= SEVERITY_ORDER[finding.severity]:
        return None

    before = finding.severity
    finding.severity = reported

    return before


def _reconcile(
    db: Session, user: User, host: str, results: list, team_id: int | None = None
) -> dict:
    """Fold one host's check results into its findings.

    The rules follow the importer's, for the same reason: a check reports what
    it observed, a person decided what it means. The one place this goes
    further is severity, and only upwards — a certificate that had thirty days
    left and now has two is not a re-litigation of anyone's judgement, it is a
    different fact. It is never lowered automatically.
    """
    counts = {"created": 0, "reopened": 0, "escalated": 0, "resolved": 0,
              "unchanged": 0, "kept_accepted": 0}
    seen_refs = set()

    for result in results:
        seen_refs.add(result.check_id)
        finding = (
            db.query(Finding)
            .filter(
                _scope(user, team_id),
                Finding.asset == host,
                Finding.source == "monitor",
                Finding.source_ref == result.check_id,
            )
            .first()
        )

        if finding is None:
            finding = Finding(
                title=result.title,
                description=result.detail,
                asset=host,
                severity=result.severity,
                status="open",
                due_date=_sla_due_date(result.severity),
                source="monitor",
                source_ref=result.check_id,
                source_severity=result.severity,
                owner_id=user.id,
                team_id=team_id,
            )
            db.add(finding)
            db.flush()
            _record_audit(
                db, user, "created", finding.id,
                f"{finding.title} · severity {finding.severity} · monitör",
            )
            counts["created"] += 1
            continue

        if finding.status == ACCEPTED_RISK:
            counts["kept_accepted"] += 1
            continue

        # The evidence is current either way, so the description is refreshed
        # even when nothing else changes: "2 gün kaldı" beating a stale "28 gün
        # kaldı" is the whole value of re-running.
        finding.description = result.detail

        escalated_from = _escalate_from_source(finding, result.severity)

        if finding.status == "fixed":
            finding.status = "open"
            finding.due_date = _sla_due_date(finding.severity)
            _record_audit(
                db, user, "updated", finding.id,
                f"{finding.title} · status fixed→open · monitör hâlâ görüyor",
            )
            counts["reopened"] += 1
        elif escalated_from is not None:
            finding.due_date = _sla_due_date(finding.severity)
            _record_audit(
                db, user, "updated", finding.id,
                f"{finding.title} · severity {escalated_from}→{finding.severity} · monitör",
            )
            counts["escalated"] += 1
        else:
            counts["unchanged"] += 1

    # Anything this monitor opened for this host that no check reported is
    # fixed — the monitor is allowed to close what the monitor opened.
    stale = (
        db.query(Finding)
        .filter(
            _scope(user, team_id),
            Finding.asset == host,
            Finding.source == "monitor",
            Finding.status.in_(("open", "triaged")),
        )
        .all()
    )

    for finding in stale:
        if finding.source_ref in seen_refs:
            continue

        finding.status = "fixed"
        _record_audit(
            db, user, "updated", finding.id,
            f"{finding.title} · status open→fixed · monitör: kontrol artık geçiyor",
        )
        counts["resolved"] += 1

    return counts


@app.post("/monitor/run")
def run_monitor(
    team_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Check every registered asset and reconcile the findings.

    Exposed as an endpoint rather than an internal scheduler: whatever already
    runs on a schedule here — cron, a CI job — can call it, and the run stays
    something a person can trigger and watch.
    """
    if team_id is not None:
        _require_membership(db, user, team_id)

    assets = (
        db.query(Asset)
        .filter(Asset.owner_id == user.id, Asset.is_active.is_(True))
        .all()
    )

    totals = {"created": 0, "reopened": 0, "escalated": 0, "resolved": 0,
              "unchanged": 0, "kept_accepted": 0}
    refused = []

    for asset in assets:
        try:
            results = run_checks(asset.host)
        except TargetRefused as error:
            # A target that was allowed at registration and is refused now has
            # changed where it points. That is worth saying out loud.
            refused.append({"host": asset.host, "reason": str(error)})
            continue

        for key, value in _reconcile(db, user, asset.host, results, team_id).items():
            totals[key] += value

    summary = (
        f"monitör: {len(assets)} varlık · {totals['created']} yeni "
        f"· {totals['reopened']} yeniden açıldı · {totals['escalated']} yükseltildi "
        f"· {totals['resolved']} kapandı · {len(refused)} reddedildi"
    )
    audit.append(
        db, user_id=user.id, action="monitored", detail=_sanitize_log(summary)
    )
    db.commit()

    return {"checked": len(assets), "refused": refused, **totals}


# --- AI analysis -------------------------------------------------------------
#
# Analyses per user per hour. The general rate limiter counts requests by
# address; this counts inference by person, because the cost of the two is not
# remotely the same and one held-down button should not spend an afternoon's
# budget.
_ai_calls: dict[int, deque] = defaultdict(deque)
_AI_WINDOW = 3600


def _ai_budget(user: User) -> None:
    calls = _ai_calls[user.id]
    now = time.time()

    while calls and calls[0] <= now - _AI_WINDOW:
        calls.popleft()

    if len(calls) >= AI_HOURLY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Saatte en fazla {AI_HOURLY_LIMIT} analiz yapılabilir.",
        )

    calls.append(now)


def _analysis_response(row: AIAnalysis) -> AIAnalysisResponse:
    return AIAnalysisResponse(
        finding_id=row.finding_id,
        created_at=row.created_at,
        provider=row.provider,
        model=row.model,
        code_sent=row.code_sent,
        risk_score=float(row.risk_score or 0),
        suggested_severity=row.suggested_severity,
        suggested_sla_hours=row.suggested_sla_hours,
        exploitability=row.exploitability,
        confidence=row.confidence,
        summary=row.summary or "",
        # Stored as one text column and split back out. A child table for at
        # most five bullet points would be a join to maintain forever.
        impact=[line for line in (row.impact or "").split("\n") if line],
        remediation=row.remediation or "",
        developer_note=row.developer_note or "",
        cwe=row.cwe or "",
        owasp=row.owasp or "",
    )


@app.get("/ai/provider", response_model=AIProviderResponse)
def ai_provider(user: User = Depends(get_current_user)):
    """Which model this installation uses, if any.

    Behind authentication: which model an organisation runs, and whether their
    findings leave the network, is not something to tell an anonymous caller.
    """
    info = ai.provider_info()

    if info is None:
        return AIProviderResponse(
            configured=False,
            note="AI analizi bu kurulumda yapılandırılmamış.",
        )

    return AIProviderResponse(
        configured=True,
        key=info.key,
        label=info.label,
        model=info.model,
        endpoint=info.endpoint,
        external=info.external,
        sends_code=info.sends_code,
        note=(
            "Bulgular ve kod bu dış servise gönderilir."
            if info.external
            else "Bulgular ve kod bu kurulumun ağından çıkmaz."
        ),
    )


@app.post("/ai/test")
def ai_test(user: User = Depends(require_role("admin"))):
    """Ask the model to answer once, and report what happened.

    A configuration check, not an analysis: it sends no finding. The endpoint
    it talks to comes from configuration — nothing in this request names it.

    Admin-only because it makes the server open an outbound connection on
    demand. Reading which model is configured is open to any user; making the
    installation reach out is not.
    """
    try:
        return {"ok": True, "detail": ai.build_provider().ping()}
    except ai.AIError as exc:
        # 200 with ok:false. The request was handled correctly; it is the model
        # that is unreachable, and a 5xx here would read as "SecureTask broke".
        return {"ok": False, "detail": str(exc)}


@app.get("/ai/analyses")
def ai_analyses(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Which findings have been analysed, and how they scored.

    Three fields, not the whole analysis. The list needs to show that a reading
    exists and roughly what it says; the reasoning behind it is worth a request
    of its own, and putting it on every row would send a page of prose per
    finding to draw one chip.

    One query rather than one per row: a list of forty findings should not be
    forty requests.
    """
    rows = (
        db.query(AIAnalysis)
        .join(Finding, Finding.id == AIAnalysis.finding_id)
        .filter(_visible_to(db, user))
        .all()
    )

    return [
        {
            "finding_id": row.finding_id,
            "risk_score": float(row.risk_score or 0),
            "suggested_severity": row.suggested_severity,
            "confidence": row.confidence,
        }
        for row in rows
    ]


@app.get("/findings/{finding_id}/source")
def finding_source(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The lines around this finding, read from the configured working tree.

    Asked for only when the report's own snippet cannot place the flagged line
    — bandit's `region` and `contextRegion` do not always nest, and the line to
    highlight can fall outside the block that came with the report.

    Nothing in the request names a file. The path and the line are the
    finding's own, and the finding is already scoped to who may see it; the
    caller supplies an id and nothing else.

    404 for every reason it cannot be served: not configured, outside the root,
    wrong kind of file, missing, or — the important one — a file that no longer
    matches what the scanner read. Distinguishing those in the response would
    turn this into a way to map the filesystem.
    """
    finding = _get_visible_finding(finding_id, user, db)

    try:
        return window_for(
            finding.asset,
            finding.evidence_line,
            finding.evidence or "",
            finding.evidence_start,
        )
    except SourceUnavailable:
        raise HTTPException(
            status_code=404,
            detail="Bu bulgu için kaynak dosya okunamıyor.",
        )


@app.get("/findings/{finding_id}/analysis", response_model=AIAnalysisResponse)
def get_analysis(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The stored analysis, if one has been run.

    Fetched on its own rather than travelling with every finding: it is only
    wanted when someone opens the panel, and on the list it would read as part
    of the finding.
    """
    finding = _get_visible_finding(finding_id, user, db)
    row = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.finding_id == finding.id)
        .one_or_none()
    )

    if row is None:
        raise HTTPException(status_code=404, detail="Bu bulgu henüz analiz edilmedi.")

    return _analysis_response(row)


@app.post("/findings/{finding_id}/analyze", response_model=AIAnalysisResponse)
def analyze_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ask the model to read this finding.

    Nothing about the finding changes. The result is stored beside it as a
    suggestion, and every rating in it stays a suggestion until a person applies
    one through the ordinary update endpoint, where it is audited like any other
    edit. This is the rule the importers already follow: a source may add work
    and argue the work is unfinished, but it may not overwrite a judgement.

    If the model is unreachable or answers with something that is not an
    analysis, the finding and its SLA are exactly as they were.
    """
    finding = _get_visible_finding(finding_id, user, db)
    _ai_budget(user)

    try:
        result = ai.analyse(finding)
    except ai.AINotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except ai.AIError as exc:
        # 502: this application is fine, the thing it asked is not. Nothing has
        # been written, so the caller can simply try again.
        raise HTTPException(status_code=502, detail=str(exc))

    row = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.finding_id == finding.id)
        .one_or_none()
    )

    if row is None:
        row = AIAnalysis(finding_id=finding.id)
        db.add(row)

    row.provider = result["provider"]
    row.model = result["model"]
    row.code_sent = result["code_sent"]
    row.who_id = user.id
    row.risk_score = result["risk_score"]
    row.suggested_severity = result["suggested_severity"]
    row.suggested_sla_hours = result["suggested_sla_hours"]
    row.exploitability = result["exploitability"]
    row.confidence = result["confidence"]
    row.summary = result["summary"]
    row.impact = "\n".join(result["impact"])
    row.remediation = result["remediation"]
    row.developer_note = result["developer_note"]
    row.cwe = result["cwe"]
    row.owasp = result["owasp"]
    row.created_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(row)

    # Logged because it is a disclosure as much as an action: it records that
    # this finding — and possibly the code quoted with it — was sent to a named
    # model at a known time, by a known person.
    _record_audit(
        db, user, "analyzed", finding.id,
        f"{finding.title} · {result['provider']}/{result['model']} · "
        f"öneri {result['suggested_severity']} · kod "
        f"{'gönderildi' if result['code_sent'] else 'gönderilmedi'}",
    )

    return _analysis_response(row)


@app.post("/risk/expire")
def expire_acceptances(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Reopen every risk acceptance whose end date has passed.

    This is the point of putting an end date on an acceptance. Without a sweep
    the date is a note; with it, a decision to live with something comes back
    on its own and has to be made again, by someone, with a second factor —
    which is how it stops being permanent by neglect.

    An endpoint rather than a background timer, for the same reason as the
    monitor: whatever already runs on a schedule can call it, and a person can
    run it and watch what happened.
    """
    today = date.today()
    expired = (
        db.query(Finding)
        .filter(
            # Anyone who can see a finding may run the sweep on it: expiry is
            # not a decision, it is the deadline someone already set arriving.
            _visible_to(db, user),
            Finding.status == ACCEPTED_RISK,
            Finding.accepted_until < today,
        )
        .all()
    )

    for finding in expired:
        until = finding.accepted_until
        finding.status = "open"
        # A reopened finding needs a live deadline; the old one is long gone.
        finding.due_date = _sla_due_date(finding.severity)
        _clear_acceptance(finding)
        _record_audit(
            db,
            user,
            "updated",
            finding.id,
            f"{finding.title} · status accepted_risk→open "
            f"· risk kabulünün süresi doldu ({until.isoformat()})",
        )

    if expired:
        audit.append(
            db,
            user_id=user.id,
            action="expired",
            detail=_sanitize_log(f"{len(expired)} risk kabulünün süresi doldu"),
        )
        db.commit()

    return {
        "reopened": len(expired),
        "findings": [f.id for f in expired],
    }


@app.get("/admin/audit/verify")
def verify_audit_chain(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Walk the audit chain and report the first entry that does not hold.

    Read-only and admin-only. It answers one question — has this log been
    changed since it was written — and names the entry where the answer stops
    being no.
    """
    return audit.verify(db)


@app.get("/audit/me", response_model=list[AuditLogResponse])
def my_audit_log(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(AuditLog)
        .filter(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(100)
        .all()
    )


# --- Admin-only: elevated access across every user's findings --------------


@app.get("/admin/findings", response_model=list[FindingResponse])
def admin_list_findings(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    return db.query(Finding).all()


@app.delete("/admin/findings/{finding_id}")
def admin_delete_finding(
    finding_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    title = finding.title

    db.delete(finding)
    db.commit()

    _record_audit(db, user, "deleted", finding_id, f"{title} (admin)")

    return {"message": "Finding deleted"}


@app.get("/admin/audit", response_model=list[AuditLogResponse])
def admin_audit_log(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(100)
        .all()
    )
