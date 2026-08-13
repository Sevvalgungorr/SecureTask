"""The audit log, as an append-only chain.

An audit log that an administrator can edit records history at that
administrator's pleasure — which, for the one record this application exists to
keep, is the same as recording nothing. So each entry carries a hash of its own
contents together with the previous entry's hash. Editing a row, deleting one,
or reordering them changes every hash after the change, and the verification
walk reports where the break is.

This does not make tampering impossible. It makes it *evident*, which is the
achievable goal: whoever rewrote the log has to rewrite every entry after it,
and anyone holding an earlier hash can still tell.
"""
import hashlib

from sqlalchemy.orm import Session

from app.models import AuditLog

# Written into the first entry's prev_hash so the start of the chain is a
# deliberate value rather than an empty column that could also mean "unset".
GENESIS = "0" * 64


def _canonical(entry: AuditLog, prev_hash: str) -> str:
    """The exact bytes an entry commits to.

    Every field that carries meaning is in here. created_at is included so a
    backdated entry breaks the chain, and id so entries cannot be reordered.
    """
    return "|".join(
        [
            prev_hash,
            str(entry.id),
            entry.created_at.isoformat(),
            str(entry.user_id or ""),
            entry.action,
            str(entry.finding_id or ""),
            entry.detail or "",
        ]
    )


def _digest(entry: AuditLog, prev_hash: str) -> str:
    return hashlib.sha256(_canonical(entry, prev_hash).encode("utf-8")).hexdigest()


def _last_entry(db: Session) -> AuditLog | None:
    return db.query(AuditLog).order_by(AuditLog.id.desc()).first()


def append(
    db: Session,
    *,
    action: str,
    user_id: int | None = None,
    finding_id: int | None = None,
    detail: str | None = None,
) -> AuditLog:
    """Add one entry and link it to the chain. Does not commit.

    The id and the server-side timestamp are part of what is signed, so the row
    is flushed to get them before the hash is computed.
    """
    previous = _last_entry(db)
    prev_hash = previous.entry_hash if previous else GENESIS

    entry = AuditLog(
        user_id=user_id, action=action, finding_id=finding_id, detail=detail,
        prev_hash=prev_hash,
    )
    db.add(entry)
    db.flush()
    db.refresh(entry)  # created_at comes from the database

    entry.entry_hash = _digest(entry, prev_hash)

    return entry


def verify(db: Session) -> dict:
    """Walk the chain from the beginning and report the first break."""
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    expected_prev = GENESIS

    for entry in entries:
        # Entries written before the chain existed carry no hash; they are
        # reported rather than silently treated as valid.
        if not entry.entry_hash:
            return {
                "ok": False,
                "checked": len(entries),
                "broken_at": entry.id,
                "reason": "zincirsiz kayıt (hash yok)",
            }

        if entry.prev_hash != expected_prev:
            return {
                "ok": False,
                "checked": len(entries),
                "broken_at": entry.id,
                "reason": "önceki kayda bağlanmıyor — araya girilmiş veya silinmiş",
            }

        if _digest(entry, entry.prev_hash) != entry.entry_hash:
            return {
                "ok": False,
                "checked": len(entries),
                "broken_at": entry.id,
                "reason": "kaydın içeriği imzasıyla uyuşmuyor — değiştirilmiş",
            }

        expected_prev = entry.entry_hash

    return {"ok": True, "checked": len(entries), "broken_at": None, "reason": None}
