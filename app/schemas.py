from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "triaged", "fixed", "accepted_risk"]


class FindingCreate(BaseModel):
    title: str
    description: str | None = None
    asset: str = ""
    severity: Severity = "medium"
    status: Status = "open"
    # Left unset, the server derives it from severity (models.SLA_DAYS).
    due_date: date | None = None
    # Required when the status is accepted_risk, refused otherwise — checked in
    # the endpoint, where the date can be compared against today.
    accepted_reason: str | None = None
    accepted_until: date | None = None


class FindingUpdate(FindingCreate):
    pass


class FindingResponse(FindingCreate):
    id: int
    owner_id: int | None = None
    # Read-only: a client does not get to claim a finding came from a scanner.
    # Only the import endpoint sets these.
    source: str = "manual"
    source_ref: str = ""
    # Who accepted the risk and when. Set by the server from the session that
    # cleared step-up; a client cannot name someone else as the approver.
    accepted_at: datetime | None = None
    accepted_by_id: int | None = None

    model_config = {
        "from_attributes": True
    }


class AssetCreate(BaseModel):
    # Hostname, optionally with a port. Validated in the endpoint, where the
    # name can actually be resolved and checked against the network policy.
    host: str
    label: str = ""


class AssetResponse(AssetCreate):
    id: int
    is_active: bool = True
    owner_id: int | None = None

    model_config = {
        "from_attributes": True
    }


class AuditLogResponse(BaseModel):
    id: int
    created_at: datetime
    user_id: int | None
    action: str
    finding_id: int | None
    detail: str | None

    model_config = {
        "from_attributes": True
    }
