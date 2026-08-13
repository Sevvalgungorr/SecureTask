"""The audit log as an append-only chain.

A log an administrator can edit records history at that administrator's
pleasure. These tests are the claim that this one cannot be edited quietly:
each test changes the stored rows directly, the way someone with database
access would, and asks the verification walk whether it noticed.
"""
from app.models import AuditLog


def _entries(db):
    return db.query(AuditLog).order_by(AuditLog.id.asc()).all()


def test_a_fresh_log_verifies(client):
    client.login_as("admin", roles=["admin"])
    client.post("/findings", json={"title": "Bir bulgu"})
    client.post("/findings", json={"title": "Başka bulgu"})

    result = client.get("/admin/audit/verify").json()
    assert result["ok"] is True
    assert result["checked"] >= 2
    assert result["broken_at"] is None


def test_each_entry_links_to_the_one_before_it(client):
    client.login_as("admin", roles=["admin"])
    for i in range(3):
        client.post("/findings", json={"title": f"Bulgu {i}"})

    entries = _entries(client.db)
    for previous, entry in zip(entries, entries[1:]):
        assert entry.prev_hash == previous.entry_hash
        assert entry.entry_hash  # every entry is signed


def test_editing_an_entry_is_detected(client):
    """The case this exists for: someone rewrites what the log says happened."""
    client.login_as("admin", roles=["admin"])
    client.post("/findings", json={"title": "Kritik bulgu"})
    client.post("/findings", json={"title": "Sonraki"})

    target = _entries(client.db)[0]
    client.db.query(AuditLog).filter(AuditLog.id == target.id).update(
        {"detail": "zararsız bir şey"}
    )
    client.db.commit()

    result = client.get("/admin/audit/verify").json()
    assert result["ok"] is False
    assert result["broken_at"] == target.id
    assert "değiştirilmiş" in result["reason"]


def test_deleting_an_entry_is_detected(client):
    """Removing the inconvenient line breaks the link to the next one."""
    client.login_as("admin", roles=["admin"])
    for i in range(3):
        client.post("/findings", json={"title": f"Bulgu {i}"})

    entries = _entries(client.db)
    client.db.query(AuditLog).filter(AuditLog.id == entries[1].id).delete()
    client.db.commit()

    result = client.get("/admin/audit/verify").json()
    assert result["ok"] is False
    assert result["broken_at"] == entries[2].id
    assert "silinmiş" in result["reason"]


def test_backdating_an_entry_is_detected(client):
    """The timestamp is part of what the entry commits to."""
    from datetime import timedelta

    client.login_as("admin", roles=["admin"])
    client.post("/findings", json={"title": "Bulgu"})

    target = _entries(client.db)[0]
    client.db.query(AuditLog).filter(AuditLog.id == target.id).update(
        {"created_at": target.created_at - timedelta(days=30)}
    )
    client.db.commit()

    result = client.get("/admin/audit/verify").json()
    assert result["ok"] is False
    assert result["broken_at"] == target.id


def test_an_unsigned_entry_is_reported_not_trusted(client):
    """Rows written before the chain existed are named, not waved through."""
    client.login_as("admin", roles=["admin"])
    client.post("/findings", json={"title": "Bulgu"})

    target = _entries(client.db)[0]
    client.db.query(AuditLog).filter(AuditLog.id == target.id).update(
        {"entry_hash": "", "prev_hash": ""}
    )
    client.db.commit()

    result = client.get("/admin/audit/verify").json()
    assert result["ok"] is False
    assert "hash yok" in result["reason"]


def test_verification_is_admin_only(client):
    client.login_as("bob")
    assert client.get("/admin/audit/verify").status_code == 403


def test_a_denied_request_is_chained_too(client):
    """The middleware writes with its own session; it must still link in."""
    client.login_as("bob")
    client.get("/admin/findings")          # 403, logged by the middleware

    client.login_as("admin", roles=["admin"])
    assert client.get("/admin/audit/verify").json()["ok"] is True
