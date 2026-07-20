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