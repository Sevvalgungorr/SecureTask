from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel

Priority = Literal["low", "medium", "high"]


class TaskCreate(BaseModel):
    title: str
    description: str | None = None
    completed: bool = False
    priority: Priority = "medium"
    due_date: date | None = None


class TaskUpdate(BaseModel):
    title: str
    description: str | None = None
    completed: bool
    priority: Priority = "medium"
    due_date: date | None = None


class TaskResponse(TaskCreate):
    id: int
    owner_id: int | None = None

    model_config = {
        "from_attributes": True
    }


class AuditLogResponse(BaseModel):
    id: int
    created_at: datetime
    user_id: int | None
    action: str
    task_id: int | None
    detail: str | None

    model_config = {
        "from_attributes": True
    }