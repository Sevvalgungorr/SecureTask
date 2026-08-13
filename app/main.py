import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app import audit
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
from app.importers import parse_nuclei
from app.monitor import TargetRefused, assert_target_allowed, run_checks
from app.models import (
    ACCEPTED_RISK,
    MAX_ACCEPTANCE_DAYS,
    MIN_ACCEPTANCE_REASON,
    SEVERITY_ORDER,
    SLA_DAYS,
    Asset,
    AuditLog,
    Finding,
    User,
)
from app.schemas import (
    AssetCreate,
    AssetResponse,
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
    # The stock docs page pulls Swagger UI from a public CDN, which this
    # application's own Content-Security-Policy forbids — so it rendered blank.
    # Replaced below with the same page served from our own files.
    docs_url=None,
)

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/docs", include_in_schema=False)
def swagger_ui():
    """The API docs, served without reaching off this host.

    Vendoring the assets rather than allowing the CDN in the CSP keeps the
    exception from existing at all: a third-party script host that can serve
    anything it likes, on a page that renders the whole API surface, is the
    supply-chain risk this application exists to track. It also means the docs
    work on a machine with no internet access, which is where an internal tool
    usually lives.
    """
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — API",
        swagger_js_url="/static/vendor/swagger-ui-bundle.js",
        swagger_css_url="/static/vendor/swagger-ui.css",
        # Default points at fastapi.tiangolo.com, which img-src 'self' blocks.
        swagger_favicon_url="/static/vendor/favicon.svg",
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
    # Filing a finding as already-accepted is the same decision as accepting one
    # later, so it meets the same bar.
    if finding.status == ACCEPTED_RISK:
        require_step_up(user)
        _validate_acceptance(finding)

    new_finding = Finding(
        title=finding.title,
        description=finding.description,
        asset=finding.asset,
        severity=finding.severity,
        status=finding.status,
        due_date=finding.due_date or _sla_due_date(finding.severity),
        owner_id=user.id,
    )

    if finding.status == ACCEPTED_RISK:
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
    finding = _get_owned_finding(finding_id, user, db)
    title = finding.title

    db.delete(finding)
    db.commit()

    _record_audit(db, user, "deleted", finding_id, title)

    return {"message": "Finding deleted"}


@app.post("/import/nuclei")
async def import_nuclei(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest a nuclei scan.

    Re-running a scan is normal, so the import is idempotent on
    `(owner, asset, source_ref)`. What it may do to an existing finding is
    deliberately narrow:

    * a finding closed as **fixed** that the scanner still sees is **reopened** —
      the evidence says it was not fixed;
    * a finding whose risk was **accepted** is left exactly as it is. The scanner
      finding it again is the expected outcome of that decision, not news, and
      an import must not quietly undo a decision that required a second factor;
    * an already-open finding is left alone — including its severity. If someone
      triaged a high down to low, the next scan does not get to overrule them.

    So a scan can add work and can prove that work was not finished. It cannot
    erase a judgement.
    """
    raw = (await request.body()).decode("utf-8", errors="replace")
    results, skipped = parse_nuclei(raw)

    if not results and not skipped:
        raise HTTPException(status_code=400, detail="Okunabilir tarama sonucu yok")

    created = reopened = escalated = unchanged = kept_accepted = 0

    for result in results:
        existing = (
            db.query(Finding)
            .filter(
                Finding.owner_id == user.id,
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
                source="nuclei",
                source_ref=result.source_ref,
                source_severity=result.severity,
                owner_id=user.id,
            )
            db.add(finding)
            db.flush()  # need the id for the audit entry
            _record_audit(
                db,
                user,
                "created",
                finding.id,
                f"{finding.title} · severity {finding.severity} · nuclei ile içe aktarıldı",
            )
            created += 1
        elif existing.status == ACCEPTED_RISK:
            kept_accepted += 1
        else:
            # Same rule as the monitor: the scanner's own rating going up is new
            # evidence, the scanner repeating itself is not.
            escalated_from = _escalate_from_source(existing, result.severity)

            if existing.status == "fixed":
                existing.status = "open"
                # A finding that came back needs a fresh deadline; keeping the
                # old one would file it as overdue the moment it reopens.
                existing.due_date = _sla_due_date(existing.severity)
                _record_audit(
                    db,
                    user,
                    "updated",
                    existing.id,
                    f"{existing.title} · status fixed→open · tarama hâlâ görüyor",
                )
                reopened += 1
            elif escalated_from is not None:
                existing.due_date = _sla_due_date(existing.severity)
                _record_audit(
                    db,
                    user,
                    "updated",
                    existing.id,
                    f"{existing.title} · severity {escalated_from}→{existing.severity} · nuclei",
                )
                escalated += 1
            else:
                unchanged += 1

    summary = (
        f"nuclei: {created} yeni · {reopened} yeniden açıldı · {escalated} yükseltildi "
        f"· {unchanged} değişmedi · {kept_accepted} risk kabul (korundu) "
        f"· {skipped} okunamadı"
    )
    # finding_id is None: this entry is about the import, not one finding.
    audit.append(
        db, user_id=user.id, action="imported", detail=_sanitize_log(summary)
    )
    db.commit()

    return {
        "created": created,
        "reopened": reopened,
        "escalated": escalated,
        "unchanged": unchanged,
        "kept_accepted": kept_accepted,
        "skipped": skipped,
    }


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


def _reconcile(db: Session, user: User, host: str, results: list) -> dict:
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
                Finding.owner_id == user.id,
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
            Finding.owner_id == user.id,
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
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Check every registered asset and reconcile the findings.

    Exposed as an endpoint rather than an internal scheduler: whatever already
    runs on a schedule here — cron, a CI job — can call it, and the run stays
    something a person can trigger and watch.
    """
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

        for key, value in _reconcile(db, user, asset.host, results).items():
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
            Finding.owner_id == user.id,
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
