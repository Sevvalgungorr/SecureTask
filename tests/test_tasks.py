"""Task CRUD, per-user ownership, and admin access."""


def test_requires_authentication(client):
    # No login_as() -> the real auth dependency runs and rejects.
    assert client.get("/tasks").status_code == 401


def test_create_and_list_own_task(client):
    client.login_as("alice")

    created = client.post("/tasks", json={"title": "Buy milk"})
    assert created.status_code == 200
    body = created.json()
    assert body["title"] == "Buy milk"
    assert body["priority"] == "medium"  # default

    listed = client.get("/tasks").json()
    assert [t["title"] for t in listed] == ["Buy milk"]


def test_tasks_are_isolated_per_user(client):
    alice = client.login_as("alice")
    task_id = client.post("/tasks", json={"title": "Alice secret"}).json()["id"]

    # Bob logs in and must not see or reach Alice's task.
    client.login_as("bob")
    assert client.get("/tasks").json() == []
    assert client.get(f"/tasks/{task_id}").status_code == 404
    assert client.delete(f"/tasks/{task_id}").status_code == 404


def test_update_preserves_priority_and_due_date(client):
    client.login_as("alice")
    task = client.post(
        "/tasks",
        json={"title": "Report", "priority": "high", "due_date": "2026-08-01"},
    ).json()

    # Toggling completion must keep priority/due_date (regression guard).
    updated = client.put(
        f"/tasks/{task['id']}",
        json={
            "title": "Report",
            "description": None,
            "completed": True,
            "priority": "high",
            "due_date": "2026-08-01",
        },
    ).json()
    assert updated["completed"] is True
    assert updated["priority"] == "high"
    assert updated["due_date"] == "2026-08-01"


def test_invalid_priority_rejected(client):
    client.login_as("alice")
    res = client.post("/tasks", json={"title": "X", "priority": "urgent"})
    assert res.status_code == 422  # not one of low/medium/high


def test_admin_sees_all_tasks_others_forbidden(client):
    client.login_as("alice")
    client.post("/tasks", json={"title": "Alice task"})

    # A non-admin cannot reach the admin endpoint.
    client.login_as("bob")
    assert client.get("/admin/tasks").status_code == 403

    # An admin sees every user's task.
    client.login_as("admin", roles=["admin"])
    all_tasks = client.get("/admin/tasks").json()
    assert any(t["title"] == "Alice task" for t in all_tasks)
