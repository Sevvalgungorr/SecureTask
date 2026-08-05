import time
from collections import defaultdict, deque
from datetime import date, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.auth import (
    callback_router,
    get_current_user,
    has_mfa,
    require_role,
    require_step_up,
    router as auth_router,
)
from app.config import SESSION_HTTPS_ONLY, SESSION_SECRET
from app.database import SessionLocal, engine, get_db
from app.models import ACCEPTED_RISK, SLA_DAYS, AuditLog, Finding, User
from app.schemas import (
    AuditLogResponse,
    FindingCreate,
    FindingResponse,
    FindingUpdate,
)

app = FastAPI(
    title="SecureTask",
    description=(
        "OpenID Connect ile korunan güvenlik bulgusu takip API'si: bulgular, "
        "kritiklik, SLA ve denetlenebilir durum değişiklikleri."
    ),
    version="2.0.0",
)

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
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # HSTS: tarayıcıya "bu siteye hep HTTPS ile gel" der (MITM/downgrade koruması).
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Permissions-Policy: uygulamanın hiç kullanmadığı güçlü tarayıcı
    # yeteneklerini (konum/mikrofon/kamera) kapatır.
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # CSP: içeriğin nereden yüklenebileceğini kısıtlar. 'unsafe-inline' gerekli,
    # çünkü tek dosyalık arayüz satır-içi <style>/<script> kullanıyor; ideali
    # bunları ayrı dosyalara taşıyıp 'unsafe-inline'ı kaldırmaktır.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
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
            db.add(AuditLog(action="access_denied", detail=detail))
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
    db.add(
        AuditLog(
            user_id=user.id,
            action=action,
            finding_id=finding_id,
            detail=detail,
        )
    )
    db.commit()


def _get_owned_finding(finding_id: int, user: User, db: Session) -> Finding:
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.owner_id == user.id)
        .first()
    )

    # A finding owned by someone else is reported as missing rather than
    # forbidden, so the endpoint does not confirm that the id exists.
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


def _sla_due_date(severity: str) -> date:
    """The remediation deadline implied by a severity, counted from today."""
    return date.today() + timedelta(days=SLA_DAYS[severity])


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


_FRONTEND = Path(__file__).parent / "static" / "index.html"


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
    # Filing a finding as already-accepted is the same decision as accepting one
    # later, so it meets the same bar.
    if finding.status == ACCEPTED_RISK:
        require_step_up(user)

    new_finding = Finding(
        title=finding.title,
        description=finding.description,
        asset=finding.asset,
        severity=finding.severity,
        status=finding.status,
        due_date=finding.due_date or _sla_due_date(finding.severity),
        owner_id=user.id,
    )

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
    return db.query(Finding).filter(Finding.owner_id == user.id).all()


@app.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_owned_finding(finding_id, user, db)


@app.put("/findings/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    finding_data: FindingUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _get_owned_finding(finding_id, user, db)

    # Only the transition is guarded. A finding that is already accepted can
    # still be retitled or re-described without a second factor; what needs one
    # is the decision to carry the risk.
    if finding_data.status == ACCEPTED_RISK and finding.status != ACCEPTED_RISK:
        require_step_up(user)

    # Read the change summary before the row is overwritten.
    detail = _describe_changes(finding, finding_data, user)

    finding.title = finding_data.title
    finding.description = finding_data.description
    finding.asset = finding_data.asset
    finding.severity = finding_data.severity
    finding.status = finding_data.status
    finding.due_date = finding_data.due_date

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
    finding = _get_owned_finding(finding_id, user, db)
    title = finding.title

    db.delete(finding)
    db.commit()

    _record_audit(db, user, "deleted", finding_id, title)

    return {"message": "Finding deleted"}


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
