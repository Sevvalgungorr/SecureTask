from datetime import datetime

from pydantic import BaseModel


class TaskCreate(BaseModel):
    title: str
    description: str | None = None
    completed: bool = False


class TaskUpdate(BaseModel):
    title: str
    description: str | None = None
    completed: bool


class TaskResponse(TaskCreate):
    id: int

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