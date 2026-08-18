from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "triaged", "fixed", "accepted_risk"]


TeamRole = Literal["member", "risk_owner"]


class TeamCreate(BaseModel):
    name: str


class TeamMemberAdd(BaseModel):
    # By id or by email — never by username, which the provider does not
    # guarantee to be unique, so naming one is not naming a person. Requiring
    # the address also means there is no directory to browse: you add someone
    # you already know how to reach.
    user_id: int | None = None
    email: str | None = None
    role: TeamRole = "member"


class TeamMemberResponse(BaseModel):
    user_id: int
    username: str
    role: TeamRole

    model_config = {
        "from_attributes": True
    }


class TeamResponse(BaseModel):
    id: int
    name: str
    # The caller's own role in this team — what the interface needs to know
    # before offering an action it would then be refused for.
    my_role: TeamRole
    members: list[TeamMemberResponse] = []

    model_config = {
        "from_attributes": True
    }


class AssigneeUpdate(BaseModel):
    # Null hands the finding back: nobody is working it, which is a state worth
    # being able to reach on purpose.
    assignee_id: int | None = None


class FindingCreate(BaseModel):
    title: str
    description: str | None = None
    asset: str = ""
    severity: Severity = "medium"
    status: Status = "open"
    # Which team may see and work this. Null keeps the finding personal — and
    # outside the separation-of-duties rule, since one person cannot be two.
    team_id: int | None = None
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
    # Who is expected to act on it. Set through its own endpoint, so a full-row
    # update cannot hand someone else's work away as a side effect.
    assignee_id: int | None = None
    # Read-only: a client does not get to claim a finding came from a scanner.
    # Only the import endpoint sets these.
    source: str = "manual"
    source_ref: str = ""
    # The remediation window's two ends. Both are the server's to set: a client
    # that could name its own creation time could file a finding that was
    # already late, or one that never ages.
    created_at: datetime
    closed_at: datetime | None = None
    # Read-only, and only ever set by an importer: the lines the report carried.
    evidence: str | None = None
    evidence_start: int | None = None
    evidence_line: int | None = None
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
