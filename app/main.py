from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.auth import (
    callback_router,
    get_current_user,
    require_role,
    router as auth_router,
)
from app.config import SESSION_HTTPS_ONLY, SESSION_SECRET
from app.database import engine, get_db
from app.models import AuditLog, Task, User
from app.schemas import AuditLogResponse, TaskCreate, TaskResponse, TaskUpdate

app = FastAPI()

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


def _record_audit(
    db: Session,
    user: User,
    action: str,
    task_id: int,
    detail: str | None = None,
) -> None:
    db.add(
        AuditLog(user_id=user.id, action=action, task_id=task_id, detail=detail)
    )
    db.commit()


def _get_owned_task(task_id: int, user: User, db: Session) -> Task:
    task = (
        db.query(Task)
        .filter(Task.id == task_id, Task.owner_id == user.id)
        .first()
    )

    # A task owned by someone else is reported as missing rather than
    # forbidden, so the endpoint does not confirm that the id exists.
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    return task


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


@app.post("/tasks", response_model=TaskResponse)
def create_task(
    task: TaskCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_task = Task(
        title=task.title,
        description=task.description,
        completed=task.completed,
        priority=task.priority,
        due_date=task.due_date,
        owner_id=user.id,
    )

    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    _record_audit(db, user, "created", new_task.id, new_task.title)

    return new_task


@app.get("/tasks", response_model=list[TaskResponse])
def get_tasks(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Task).filter(Task.owner_id == user.id).all()


@app.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_owned_task(task_id, user, db)


@app.put("/tasks/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    task_data: TaskUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    task = _get_owned_task(task_id, user, db)

    task.title = task_data.title
    task.description = task_data.description
    task.completed = task_data.completed
    task.priority = task_data.priority
    task.due_date = task_data.due_date

    db.commit()
    db.refresh(task)

    _record_audit(db, user, "updated", task.id, task.title)

    return task


@app.delete("/tasks/{task_id}")
def delete_task(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    task = _get_owned_task(task_id, user, db)
    title = task.title

    db.delete(task)
    db.commit()

    _record_audit(db, user, "deleted", task_id, title)

    return {"message": "Task deleted"}


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


# --- Admin-only: elevated access across every user's tasks -----------------


@app.get("/admin/tasks", response_model=list[TaskResponse])
def admin_list_tasks(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    return db.query(Task).all()


@app.delete("/admin/tasks/{task_id}")
def admin_delete_task(
    task_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    task = db.query(Task).filter(Task.id == task_id).first()

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    title = task.title

    db.delete(task)
    db.commit()

    _record_audit(db, user, "deleted", task_id, f"{title} (admin)")

    return {"message": "Task deleted"}


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
