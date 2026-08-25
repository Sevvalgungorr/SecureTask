from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel

Severity = Literal["low", "medium", "high", "critical"]
# "awaiting_retest" sits between triaged and fixed: the developer says it is
# done, the tester has not agreed. It is an OPEN state — the SLA clock keeps
# running — because a finding that stops counting when its author says so is a
# finding nobody verifies.
Status = Literal["open", "triaged", "awaiting_retest", "fixed", "accepted_risk"]
PentestStatus = Literal["planned", "in_progress", "awaiting_retest", "completed", "cancelled"]
ScopeStatus = Literal["not_started", "in_progress", "completed", "not_applicable"]
RetestResult = Literal["passed", "failed"]


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
    # The engagement this came out of, when it came out of one. Read-only here:
    # a finding is attached to a pentest by being filed through it.
    pentest_id: int | None = None
    # Read-only, and only ever set by an importer: the lines the report carried.
    evidence: str | None = None
    evidence_start: int | None = None
    evidence_line: int | None = None
    # What one scanner reported that has no field of its own — the package and
    # fixed version behind a dependency vulnerability, the rule and type behind
    # a leaked credential. Read-only for the same reason `source` is: a client
    # does not get to claim a scanner said something.
    #
    # For a secret finding there is no key here holding the credential, and no
    # code that would add one. What the scanner found is described; it is not
    # carried.
    details: dict | None = None
    # Who accepted the risk and when. Set by the server from the session that
    # cleared step-up; a client cannot name someone else as the approver.
    accepted_at: datetime | None = None
    accepted_by_id: int | None = None

    model_config = {
        "from_attributes": True
    }


class PentestCreate(BaseModel):
    name: str
    asset: str = ""
    kind: Literal["web", "api", "internal"] = "web"
    # No production value. An engagement against production is a decision
    # someone writes deliberately rather than picks from a menu.
    environment: Literal["test", "staging"] = "test"
    started_on: date | None = None
    due_on: date | None = None
    description: str | None = None
    team_id: int | None = None
    tester_id: int | None = None


class PentestUpdate(BaseModel):
    status: PentestStatus | None = None
    tester_id: int | None = None
    due_on: date | None = None


class ScopeUpdate(BaseModel):
    status: ScopeStatus
    note: str | None = None


class RetestCreate(BaseModel):
    result: RetestResult
    note: str | None = None


# --- CI/CD ------------------------------------------------------------------
#
# What a pipeline is allowed to say. Every field a machine could use to reach
# somewhere it should not is absent by design rather than validated:
#
#   * no `team_id` or `owner_id` — the tenant comes from the registration
#   * no `url`, `host` or `target` — the DAST address is resolved server-side
#   * no `path`, `command` or `script` — nothing here starts a process
#   * no `severity` override — the scanner's report decides, then a person does

ScanType = Literal["sast", "sca", "secret"]
DeploymentState = Literal["started", "succeeded", "failed"]
# Only staging. Production deployment tracking is absent for the same reason
# production is absent from a pentest engagement's environment list.
Environment = Literal["staging"]


class CiIntegrationCreate(BaseModel):
    """Registering a repository. Done by a person, never by CI."""

    repository: str
    project: str = ""
    label: str = ""
    # A registered DAST target NAME, checked against DAST_TARGETS in the
    # endpoint. Never a URL: a field that could carry one would let whoever
    # sets up an integration point the scanner at anything reachable.
    dast_target: str = ""
    team_id: int | None = None


class CiIntegrationResponse(BaseModel):
    """What may be shown about an integration.

    There is no token field. The value exists exactly once, in the response
    that creates it, and is never readable again — a credential that can be
    fetched back is a credential in every screenshot of this page.
    """

    id: int
    repository: str
    provider: str
    project: str
    label: str
    dast_target: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None
    team_id: int | None = None

    model_config = {
        "from_attributes": True
    }


class CiIntegrationCreated(CiIntegrationResponse):
    """The one response that carries a token, and says so."""

    token: str
    note: str = (
        "Bu jeton bir daha gösterilmeyecek. GitHub Secrets içine "
        "SECURETASK_CI_TOKEN olarak kaydet."
    )


class PipelineContext(BaseModel):
    """Which run a report belongs to. Sent with everything CI posts."""

    repository: str
    external_run_id: str
    branch: str = ""
    commit_sha: str = ""
    pull_request: int | None = None
    external_url: str = ""


class CiScanResult(PipelineContext):
    """One scanner's output, as the pipeline already produced it.

    `payload` is the scanner's own report, unmodified — SARIF from bandit, JSON
    from pip-audit, JSON from gitleaks. It goes to the reader that already
    exists for that format, so nothing about how a report becomes a finding is
    duplicated here.

    There is no `scanner` field. It is derived from `scan_type` server-side:
    a report that could name its own tool could file findings as "bandit" and
    have them close a real bandit scan's findings on the next run.
    """

    scan_type: ScanType
    # Whether the scanner itself ran. False means it could not — not installed,
    # crashed, timed out — and the run is recorded as such rather than as an
    # empty, clean-looking result.
    succeeded: bool = True
    error: str = ""
    payload: str = ""


class CiDeployment(PipelineContext):
    """A report that an external system deployed something.

    Not an instruction. There is nothing in this model an application could
    deploy *from*: no host, no credential, no artefact, no command.
    """

    state: DeploymentState
    environment: Environment = "staging"
    # The external system's own identifier for the deployment, for tracing back.
    deployment_ref: str = ""


class CiDastRequest(PipelineContext):
    """Ask for a post-deployment scan of the environment that was deployed.

    The target is a registered NAME resolved from the integration, and the URL
    comes from DAST_TARGETS on the server — the same rule the Scans page
    follows, for the same reason.
    """

    environment: Environment = "staging"


class ScanRunResponse(BaseModel):
    id: int
    kind: str
    scanner: str
    status: str
    created: int = 0
    reopened: int = 0
    unchanged: int = 0
    resolved: int = 0
    total: int = 0
    blocking: int = 0
    note: str = ""
    error: str = ""
    started_at: datetime
    finished_at: datetime | None = None

    model_config = {
        "from_attributes": True
    }


class PipelineResponse(BaseModel):
    id: int
    repository: str
    provider: str
    branch: str
    commit_sha: str
    pull_request: int | None = None
    external_run_id: str
    external_url: str = ""
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    # The code half and the release half, kept apart on purpose: a successful
    # deployment is not a safe release, and one field for both is how the two
    # come to be read as one.
    security_gate: str
    gate_reason: str = ""
    environment: str = ""
    deployment_status: str = ""
    deployed_at: datetime | None = None
    dast_status: str = ""
    release_status: str
    release_reason: str = ""
    scans: list[ScanRunResponse] = []

    model_config = {
        "from_attributes": True
    }


class GateResponse(BaseModel):
    """What CI asks for after reporting. Deliberately small.

    A pipeline may know whether it passed and why. It may not read the findings
    — that needs a person with a session, and a token that could would be a
    read credential for the whole tenant sitting in a repository's secrets.
    """

    security_gate: str
    gate_reason: str = ""
    release_status: str
    release_reason: str = ""
    blocking: int = 0
    completed_scans: list[str] = []
    missing_scans: list[str] = []


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


class AIProviderResponse(BaseModel):
    """What the interface may know about the model being used.

    There is no field for the key, redacted or otherwise. A response that can
    carry a credential is a credential in a screenshot, a bug report, a log.
    """

    configured: bool
    key: str = ""
    label: str = ""
    model: str = ""
    endpoint: str = ""
    # Whether findings leave the network. Shown in as many words: nobody should
    # have to read a config file to learn their vulnerability list is being
    # posted to a third party.
    external: bool = False
    sends_code: bool = False
    note: str = ""


class AISourceResponse(BaseModel):
    """One reference passage that was given to the model.

    Resolved from the knowledge base at read time, not stored alongside the
    analysis: an identifier that no longer exists is simply dropped, so a
    citation is only shown while the thing it points at is still there.
    """

    source: str
    id: str
    title: str
    summary: str = ""
    reference: str = ""


class AIAnalysisResponse(BaseModel):
    """A model's reading of a finding. Every rating here is a suggestion.

    Named `suggested_*` throughout because that is what they are: nothing in
    this response has been applied to the finding, and applying one is a
    separate, audited act by a person.
    """

    finding_id: int
    created_at: datetime
    provider: str
    model: str
    # Whether the quoted source was in the request — the difference between a
    # judgement and a guess, and the record of what left the building.
    code_sent: bool
    risk_score: float
    suggested_severity: Severity
    suggested_sla_hours: int | None = None
    exploitability: str
    # How sure the model is. Asked for on purpose: three lines of context often
    # cannot settle whether an input is reachable, and a confident answer to an
    # unanswerable question is the failure mode worth seeing.
    confidence: str
    summary: str = ""
    impact: list[str] = []
    remediation: str = ""
    developer_note: str = ""
    cwe: str = ""
    owasp: str = ""
    # The passages that were actually in the request. Empty means the model
    # answered from its own knowledge — which the interface says plainly rather
    # than implying a lookup happened.
    sources: list[AISourceResponse] = []
    kb_version: str = ""


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
