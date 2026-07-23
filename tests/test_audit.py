"""Audit logging and the per-user history endpoint."""


def test_actions_are_recorded_in_audit(client):
    client.login_as("admin", roles=["admin"])

    task_id = client.post("/tasks", json={"title": "Track me"}).json()["id"]
    client.put(
        f"/tasks/{task_id}",
        json={"title": "Track me", "description": None, "completed": True,
              "priority": "medium", "due_date": None},
    )
    client.delete(f"/tasks/{task_id}")

    actions = [e["action"] for e in client.get("/admin/audit").json()]
    assert "created" in actions
    assert "updated" in actions
    assert "deleted" in actions


def test_audit_survives_task_deletion(client):
    client.login_as("admin", roles=["admin"])
    task_id = client.post("/tasks", json={"title": "Doomed"}).json()["id"]
    client.delete(f"/tasks/{task_id}")

    entry = next(
        e for e in client.get("/admin/audit").json()
        if e["action"] == "deleted" and e["task_id"] == task_id
    )
    assert entry["detail"] == "Doomed"


def test_audit_me_returns_only_own_entries(client):
    alice = client.login_as("alice")
    client.post("/tasks", json={"title": "Alice does this"})

    bob = client.login_as("bob")
    client.post("/tasks", json={"title": "Bob does that"})

    # Bob's history has only Bob's action.
    bob_history = client.get("/audit/me").json()
    assert all(e["user_id"] == bob.id for e in bob_history)
    assert any(e["detail"] == "Bob does that" for e in bob_history)
    assert not any(e["detail"] == "Alice does this" for e in bob_history)


def test_audit_me_requires_authentication(client):
    assert client.get("/audit/me").status_code == 401
