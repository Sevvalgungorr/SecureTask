from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    UniqueConstraint,
    event,
    func,
)

from app.database import Base

# Remediation window per severity, in days. A finding without an explicit due
# date gets one from here, so nothing lands in the list without a deadline.
SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}

# Both close a finding, but not the same way: one removes the problem, the
# other keeps it and records that someone decided to live with it.
ACCEPTED_RISK = "accepted_risk"
# The developer says it is fixed; the tester has not agreed yet. Deliberately
# NOT a closed status: the hole is still there until someone checks, and a
# finding that stops counting the moment its author says so is a finding
# nobody verifies. The SLA clock keeps running through it.
AWAITING_RETEST = "awaiting_retest"
CLOSED_STATUSES = ("fixed", ACCEPTED_RISK)

# What a pentest engagement is doing, as opposed to what a finding is doing.
# Kept separate on purpose: an engagement can be finished while findings from
# it are still open, and a finding can be closed long after the report.
PENTEST_STATUSES = ("planned", "in_progress", "awaiting_retest", "completed", "cancelled")

# The areas a web/API engagement is usually divided into. A starting list, not
# a fixed one — an engagement writes its own rows and may add to them.
DEFAULT_SCOPE = (
    "Authentication",
    "Authorization",
    "Session Management",
    "API Security",
    "Input Validation",
    "Business Logic",
    "File Upload",
    "Error Handling",
)

# Scope item states. "not_applicable" is not a gap: deciding an area does not
# apply is a tested conclusion, so it counts as covered when progress is
# computed.
SCOPE_DONE = ("completed", "not_applicable")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The longest a risk may be accepted for. Not a limit for its own sake: an
# acceptance that never expires is how risk accumulates — someone says "for
# now" and nobody looks again.
MAX_ACCEPTANCE_DAYS = 90

# Short enough to write, long enough that "ok" does not pass for an argument.
MIN_ACCEPTANCE_REASON = 15

# What a person may do inside a team. Everyone in a team can file findings,
# triage them, take one and fix it. Accepting a risk — deciding the
# organisation will live with a known hole — is the one act kept separate,
# because it is the one that closes a finding without removing the problem.
TEAM_MEMBER = "member"
TEAM_RISK_OWNER = "risk_owner"
TEAM_ROLES = (TEAM_MEMBER, TEAM_RISK_OWNER)


class Team(Base):
    """The group a finding belongs to, and the reason the controls mean anything.

    Every guard in this application constrains somebody: the second factor, the
    written reason, the chained log. With one person holding the whole list —
    finder, fixer and approver at once — there is nobody to constrain and the
    guards are ceremony. A team is what puts a second person in the room.
    """

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("name", name="uq_teams_name"),)

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Whoever created it. Kept so a team is never left without an origin, even
    # after its first risk owner leaves.
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))


class TeamMember(Base):
    """One person's membership of one team, and what they may do in it."""

    __tablename__ = "team_members"
    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_members_team_user"),
    )

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(
        Integer, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role = Column(String(20), nullable=False, server_default=TEAM_MEMBER)


class Finding(Base):
    """A security finding: something wrong on an asset, and its remediation."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    # Evidence: what was observed, how it was reproduced.
    description = Column(String)
    # The system the finding was observed on (host, service, repository).
    asset = Column(String(255), nullable=False, server_default="")
    # low / medium / high / critical — existing rows default to medium.
    severity = Column(String(10), nullable=False, server_default="medium")
    # open / triaged / fixed / accepted_risk. A finding is never deleted from
    # the workflow by being "done"; it is either fixed or the risk is accepted,
    # and the difference matters when the log is read back.
    status = Column(String(20), nullable=False, server_default="open")
    # Remediation deadline. Derived from severity at creation time when the
    # reporter does not set one — see SLA_DAYS.
    due_date = Column(Date)
    # When the clock started. A deadline on its own says how much time is left;
    # it takes the start to say how much of the window has been used, which is
    # the difference between "due in three days" and "nobody has touched this
    # for eighty-seven days".
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # When it stopped. Set against the deadline this is whether the SLA was met
    # — the measure the whole remediation window exists to produce. Maintained
    # by the listener below rather than by hand; see there for why.
    closed_at = Column(DateTime(timezone=True))
    # Where the finding came from: "manual" or a scanner name. Together with
    # source_ref this is what makes a re-scan update the existing finding
    # instead of filing a duplicate.
    source = Column(String(30), nullable=False, server_default="manual")
    # The scanner's own identifier for the rule that fired (nuclei's
    # template-id). Empty for anything typed in by hand.
    source_ref = Column(String(255), nullable=False, server_default="")
    # --- The risk acceptance, when there is one ---------------------------
    #
    # Accepting a risk is the only decision here that leaves a known hole open
    # on purpose, so it is the only one that has to be argued for, owned, and
    # given an end. These are cleared when the acceptance ends; the audit log
    # keeps the history.
    accepted_reason = Column(String(2000))
    # No acceptance is permanent. Past this date the finding reopens by itself.
    accepted_until = Column(Date)
    accepted_at = Column(DateTime(timezone=True))
    accepted_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))

    # The lines the scanner was looking at when it fired, as the report itself
    # carried them. Nothing is fetched to build this: the repository is never
    # cloned, so the only code here is the code the report chose to include.
    #
    # It can contain the very thing the rule flagged — a hardcoded-secret
    # finding quotes the secret. That is why it inherits the finding's access
    # control rather than living anywhere more public, and why it is capped.
    #
    # For a secret-scanning finding the snippet is **masked before it is ever
    # built**, in the parser, so what lands here is `API_KEY = "ghp_****"` and
    # the real value exists nowhere in this process after the scanner's output
    # is read. See app/importers.py: parse_gitleaks.
    evidence = Column(String(4000))
    # Where the snippet starts, and which line inside it is the finding.
    evidence_start = Column(Integer)
    evidence_line = Column(Integer)
    # What a particular scanner reported that has no column of its own: the
    # package and fixed version for a dependency vulnerability, the rule and
    # secret *type* for a leaked credential.
    #
    # One JSON column rather than six nullable ones that are empty for every
    # other kind of finding. It is read-only from outside — nothing in a
    # request writes here, only an importer — so it holds what a scanner said
    # and not what a caller claimed. A real secret is never one of the values;
    # that is guaranteed where the dict is built, not here.
    details = Column(JSON)

    # What the source last rated this, as opposed to what the row now says.
    # Keeping the two apart is what lets a re-run tell "the evidence got worse"
    # (the source's rating rose) from "a person disagreed with the tool" (the
    # source is saying exactly what it said last time). Only the first is a
    # reason to overwrite a human's severity.
    source_severity = Column(String(10), nullable=False, server_default="")
    # Who filed it. Not "who is responsible for it" — that is assignee_id — and
    # deliberately not who may close it: the reporter is the one person barred
    # from accepting this finding's risk.
    owner_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The team that can see and work this finding. Null means it is personal:
    # visible only to the reporter, and outside the separation-of-duties rule,
    # because one person cannot be two people.
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"), index=True)
    # The engagement this came out of, when it came out of one. Null for
    # everything a scanner or a monitor filed — which is most of them.
    pentest_id = Column(
        Integer, ForeignKey("pentests.id", ondelete="SET NULL"), index=True
    )
    # Who is expected to do something about it. Null means nobody has taken it,
    # which is a state worth being able to see rather than hiding behind a
    # default.
    assignee_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))

    __table_args__ = (
        # The lookup an import does for every incoming result.
        Index("ix_findings_dedupe", "owner_id", "asset", "source_ref"),
    )


@event.listens_for(Finding.status, "set")
def _stamp_closed_at(finding, new, old, initiator):
    """Keep closed_at in step with status, wherever the status is set.

    Six places move a finding across that line: an edit, filing one as already
    accepted, an import reopening something marked fixed, the monitor closing a
    check that now passes, the monitor reopening one that does not, and an
    acceptance expiring. A timestamp maintained at six call sites is a
    timestamp that is wrong at the seventh, and this one decides whether an SLA
    was met — so it is derived here, at the one place status is defined, and
    cannot be forgotten.
    """
    if new == old:
        return

    if new in CLOSED_STATUSES:
        # Only the first close stamps it. fixed → accepted_risk is a change of
        # reason, not a reopening, and the finding never went back on the list.
        if old not in CLOSED_STATUSES:
            finding.closed_at = datetime.now(timezone.utc)
    else:
        finding.closed_at = None


class AIAnalysis(Base):
    """What a model said about one finding, the last time it was asked.

    A separate table rather than columns on the finding, for one reason that
    matters more than tidiness: these fields are an *opinion about* the row, not
    part of it. Sitting on the finding they would be read as the finding's own
    values, and the first thing someone would do is sort by `risk_score` as
    though the application had rated anything. Here, the suggestion has to be
    fetched deliberately and applied deliberately.

    One row per finding — the current reading, not a history. Re-analysing
    replaces it; what was applied from it is in the audit log, which is the
    record meant to be read back.
    """

    __tablename__ = "ai_analyses"
    __table_args__ = (
        UniqueConstraint("finding_id", name="uq_ai_analyses_finding"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(
        Integer,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Which model said it, and where it ran. An analysis without provenance is
    # an anonymous opinion, and six months later nobody can tell whether it came
    # from a model that had the code in front of it or one guessing at a title.
    provider = Column(String(30), nullable=False, server_default="")
    model = Column(String(120), nullable=False, server_default="")
    # Whether the quoted source was part of the request. This is the difference
    # between a judgement and a guess, and it is also the disclosure record: it
    # says whether that code left the building.
    code_sent = Column(Boolean, nullable=False, server_default="false")
    who_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))

    # The model's reading. `suggested_*` are named for what they are: nothing
    # here is ever copied onto the finding without a person doing it.
    risk_score = Column(Numeric(4, 1), nullable=False, server_default="0")
    suggested_severity = Column(String(10), nullable=False, server_default="medium")
    suggested_sla_hours = Column(Integer)
    exploitability = Column(String(10), nullable=False, server_default="medium")
    confidence = Column(String(10), nullable=False, server_default="low")
    summary = Column(String(1000))
    impact = Column(String(1200))
    remediation = Column(String(1200))
    developer_note = Column(String(1000))
    cwe = Column(String(20), nullable=False, server_default="")
    owasp = Column(String(60), nullable=False, server_default="")

    # Which reference passages were in the request, as identifiers only —
    # "CWE:CWE-89,OWASP:A03". The text lives in app/knowledge/, in one place,
    # so correcting a passage corrects every analysis that cited it. Copying it
    # here would freeze whatever was true the day the analysis ran.
    #
    # These come from the retriever, never from the answer. A model asked to
    # list its sources produces plausible ones.
    sources = Column(String(500), nullable=False, server_default="")
    # Which body of knowledge produced this reading. Empty when nothing was
    # retrieved, which is also how "no RAG here" is recorded.
    kb_version = Column(String(30), nullable=False, server_default="")


class ScanRun(Base):
    """One run of a static analyser over a registered project.

    Kept because a scan is an event with an outcome, not just a way of getting
    findings: who started it, what it ran over, whether it worked, and what it
    produced. Without the row a failed scan leaves no trace at all, and "I ran
    it and nothing happened" has no answer.

    The findings themselves are ordinary findings — there is no separate
    store for scanner results, because the rules about what a report may do to
    a decision are the same whether the report was uploaded or produced here.
    """

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    # The project's registered *name*, not its path. A path in a row invites a
    # later feature to read it back out of the database and use it.
    project = Column(String(80), nullable=False)
    # "sast" | "sca" | "secret" | "dast". One table for all four because a run
    # is a run — who started it, over what, with what outcome. The kind matters
    # for what the row *means* (a directory, a manifest, a running system), not
    # for how it is kept.
    kind = Column(String(10), nullable=False, server_default="sast")
    scanner = Column(String(30), nullable=False, server_default="bandit")
    # queued → running → completed | failed | scanner_unavailable
    #
    # The last one is its own outcome rather than a kind of failure: "gitleaks
    # is not installed on this machine" is a thing the operator can fix in a
    # minute, and burying it in the same red box as "the scanner crashed"
    # makes them go looking for the wrong problem.
    status = Column(String(20), nullable=False, server_default="queued")
    # Something true about the run that is not an error: how many requirement
    # lines were skipped because they were not pinned, for instance. A scan
    # that quietly examined less than the operator thinks it did is worse than
    # one that failed.
    note = Column(String(200), nullable=False, server_default="")
    started_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at = Column(DateTime(timezone=True))
    # What the import did, so the page can say "5 new, 3 unchanged" rather than
    # only a total.
    created = Column(Integer, nullable=False, server_default="0")
    reopened = Column(Integer, nullable=False, server_default="0")
    unchanged = Column(Integer, nullable=False, server_default="0")
    # Findings this scan no longer reports, closed because the scan covered
    # the tree they live in. See _resolve_stale() for why that qualifier is
    # doing real work.
    resolved = Column(Integer, nullable=False, server_default="0")
    total = Column(Integer, nullable=False, server_default="0")
    # Why it failed, in words a person can act on. Empty on success.
    error = Column(String(400), nullable=False, server_default="")
    # How many of the findings this run reported are **critical and still
    # open**. Counted at ingest time rather than asked for later, because
    # "critical findings in this tenant" is a different question: it includes
    # other repositories, older scans and things this run never looked at. A
    # gate has to judge what this run found.
    #
    # An accepted risk does not count. Someone argued for it with a second
    # factor and an expiry; a gate that fails anyway makes the acceptance
    # meaningless and teaches people to switch the gate off.
    blocking = Column(Integer, nullable=False, server_default="0")
    # The pipeline this run belongs to, when it came from one. Null for a scan
    # somebody started from the Scans page — the same row either way, because a
    # run is a run.
    pipeline_id = Column(
        Integer, ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True
    )
    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"), index=True)


class Pentest(Base):
    """A human-run security assessment, and the process around it.

    This is not a scanner. Nothing here executes anything against a target —
    the module manages an engagement: what is in scope, how far it has got,
    what was found, and whether the fixes were verified. The automated half of
    this application lives in `scan_runs`, and the two are kept apart because
    they answer to different things: one to a schedule, one to a person.
    """

    __tablename__ = "pentests"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    # What is being tested, in the same vocabulary findings use.
    asset = Column(String(255), nullable=False, server_default="")
    kind = Column(String(30), nullable=False, server_default="web")
    # test / staging / …. There is no production value offered by the
    # interface; an engagement against production is a decision someone types
    # in deliberately.
    environment = Column(String(30), nullable=False, server_default="test")
    status = Column(String(20), nullable=False, server_default="planned")
    started_on = Column(Date)
    due_on = Column(Date)
    description = Column(String(2000))
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Who may see and work it — the same rule findings follow. Null keeps the
    # engagement personal.
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"), index=True)
    # The person doing the testing, when that is someone other than whoever
    # created the engagement.
    tester_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))


class PentestScope(Base):
    """One area of an engagement, and whether it has been looked at.

    Progress is computed from these rows rather than typed in. A percentage
    somebody entered by hand is a number about how they feel; this one is a
    count of areas actually closed out.
    """

    __tablename__ = "pentest_scopes"

    id = Column(Integer, primary_key=True, index=True)
    pentest_id = Column(
        Integer, ForeignKey("pentests.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name = Column(String(120), nullable=False)
    # not_started / in_progress / completed / not_applicable
    status = Column(String(20), nullable=False, server_default="not_started")
    note = Column(String(500))


class Retest(Base):
    """One verification attempt on one finding.

    Kept as rows rather than a flag because the history is the point: a finding
    that failed retest twice before passing is a different story from one that
    passed first time, and the difference matters when the engagement is read
    back months later.
    """

    __tablename__ = "retests"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(
        Integer, ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # passed / failed
    result = Column(String(10), nullable=False)
    note = Column(String(1000))
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    tester_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))


class Asset(Base):
    """A host this installation is allowed to check.

    Monitoring means the server makes connections on a user's behalf, so the
    target cannot be a free-form string handed in with the request. It has to be
    registered first, which turns "scan anything" into "check the things we
    already said are ours".
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("owner_id", "host", name="uq_assets_owner_host"),
    )

    id = Column(Integer, primary_key=True, index=True)
    # Hostname, optionally with a port. No scheme, no path: a host is what is
    # checked, and allowing a path would invite the URL to carry more than it
    # should.
    host = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False, server_default="")
    is_active = Column(Boolean, nullable=False, server_default="true")
    owner_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("oidc_issuer", "oidc_sub", name="uq_users_oidc_identity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    # The provider does not guarantee a unique or stable name or email across
    # accounts, so identity is keyed on (issuer, sub) instead.
    username = Column(String(255), nullable=False)
    email = Column(String(255), index=True)
    # Null for identities that authenticate through the provider rather than a
    # local password.
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True, nullable=False)
    oidc_issuer = Column(String(255), nullable=False, index=True)
    oidc_sub = Column(String(255), nullable=False, index=True)


# --- The pipeline ------------------------------------------------------------
#
# A scan is one tool's opinion. A pipeline is the decision that follows from
# all of them together, at a particular commit, on the way to a particular
# environment — and it is a different thing to record, because "did bandit
# find something" and "may this go out" are different questions.
#
# What is deliberately NOT here: anything that deploys. There is no host, no
# key, no command, no cloud credential in these tables, because SecureTask does
# not deploy. The external CI/CD system does that and tells this application
# what happened; this application decides what it means.

# The scans a pipeline has to have completed before a gate can say anything at
# all. Missing one is not a pass and not a failure — it is INCOMPLETE, which is
# the honest third answer.
REQUIRED_SCANS = ("sast", "sca", "secret")

GATE_PASSED = "passed"
GATE_FAILED = "failed"
GATE_INCOMPLETE = "incomplete"

# What blocks a gate. Only the top band, on purpose: a gate that fails on
# anything at all is a gate somebody turns off in a week.
GATE_BLOCKS_AT = "critical"

RELEASE_READY = "ready"
RELEASE_NOT_READY = "not_ready"
RELEASE_INCOMPLETE = "incomplete"

DEPLOY_STARTED = "started"
DEPLOY_SUCCEEDED = "succeeded"
DEPLOY_FAILED = "failed"
DEPLOY_STATES = (DEPLOY_STARTED, DEPLOY_SUCCEEDED, DEPLOY_FAILED)

# The one environment this version will record a deployment to. Production is
# absent for the same reason it is absent from a pentest engagement: shipping
# to it is a decision someone writes deliberately, not one they pick from a
# list a machine can send.
DEPLOY_ENVIRONMENTS = ("staging",)


class CiIntegration(Base):
    """One repository, allowed to file findings into one tenant.

    Two things live here, and both are refusals of something simpler.

    **The token is not stored.** Only its SHA-256 is. A credential this
    application can read back is a credential in a database dump, a backup, a
    support session and a screenshot — and there is no operation that needs the
    original, because verifying one only needs to hash what was presented.

    **The repository name in a request is not trusted.** It is looked up here,
    and the tenant comes from *this row*, not from the request. Without that, a
    CI job holding any valid token could name someone else's repository and
    file findings into their list.
    """

    __tablename__ = "ci_integrations"

    id = Column(Integer, primary_key=True, index=True)
    # "owner/name" as the provider writes it. Unique: two rows claiming one
    # repository would make which tenant receives its findings a matter of
    # which row was read first.
    repository = Column(String(200), nullable=False, unique=True, index=True)
    provider = Column(String(30), nullable=False, server_default="github")
    # What this repository is called inside SecureTask — the name that lands in
    # ScanRun.project. Set here by a person, never by CI.
    project = Column(String(80), nullable=False, server_default="")
    # SHA-256 of the token. Indexed because verification is a lookup by hash:
    # the presented token is hashed and matched, so there is no scan and no
    # comparison against a stored secret.
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    # Shown in the interface so a person can tell two integrations apart
    # without either token being shown again. Not derived from the token.
    label = Column(String(80), nullable=False, server_default="")
    # Which registered DAST target this repository's staging deployment maps
    # to, by NAME. The URL is resolved from DAST_TARGETS at scan time and never
    # travels in a request — the same rule the scan endpoint already follows.
    dast_target = Column(String(80), nullable=False, server_default="")
    is_active = Column(Boolean, nullable=False, server_default="true")
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at = Column(DateTime(timezone=True))
    # The tenant. Findings filed through this integration belong here, and a
    # request cannot name anywhere else.
    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"), index=True)


class PipelineRun(Base):
    """One run of a repository's pipeline, and what it is allowed to conclude.

    Kept separately from `scan_runs` because it answers a different question.
    A scan run says what a tool reported; this says whether the commit may
    proceed — which depends on several tools, on whether the required ones ran
    at all, and later on whether the thing that was deployed still stood up to
    being scanned.

    The two halves are deliberately separate columns rather than one status:
    **`security_gate` is about the code, `release_status` is about the
    release**, and collapsing them is how "the deployment succeeded" comes to
    be read as "the release is safe".
    """

    __tablename__ = "pipeline_runs"
    __table_args__ = (
        # Idempotency, enforced by the database rather than by remembering to
        # check. A CI provider retries; a retried request must land on the row
        # it already made, not a second one.
        UniqueConstraint("integration_id", "external_run_id", name="uq_pipeline_run"),
    )

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer,
        ForeignKey("ci_integrations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Echoed from the integration rather than the request, so a row cannot
    # claim a repository its token does not own.
    repository = Column(String(200), nullable=False)
    provider = Column(String(30), nullable=False, server_default="github")
    branch = Column(String(200), nullable=False, server_default="")
    commit_sha = Column(String(64), nullable=False, server_default="")
    pull_request = Column(Integer)
    # The provider's own identifier for the run. Together with the integration
    # this is what makes a retry idempotent.
    external_run_id = Column(String(120), nullable=False)
    external_url = Column(String(500), nullable=False, server_default="")

    status = Column(String(20), nullable=False, server_default="running")
    started_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at = Column(DateTime(timezone=True))

    # --- the code half ---
    security_gate = Column(String(20), nullable=False, server_default=GATE_INCOMPLETE)
    # Why, in words a person can act on. A gate that says only "failed" sends
    # someone to read four scan reports to find out what it meant.
    gate_reason = Column(String(300), nullable=False, server_default="")

    # --- the release half ---
    environment = Column(String(30), nullable=False, server_default="")
    deployment_status = Column(String(20), nullable=False, server_default="")
    deployment_ref = Column(String(120), nullable=False, server_default="")
    deployed_at = Column(DateTime(timezone=True))
    # Not a copy of the DAST scan's status: "the scanner is not installed" and
    # "the scan found something" are different answers here, and both have to
    # survive into the release decision.
    dast_status = Column(String(30), nullable=False, server_default="")
    release_status = Column(
        String(20), nullable=False, server_default=RELEASE_INCOMPLETE
    )
    release_reason = Column(String(300), nullable=False, server_default="")

    owner_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="SET NULL"), index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    # Set by the database at insert time, so the log timestamp does not depend
    # on the application clock.
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    # Keep the log even if the user is later removed.
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    action = Column(String(20), nullable=False)  # created / updated / deleted
    # Tamper-evidence. Each entry hashes its own contents together with the
    # previous entry's hash, so the log can only be appended to: editing or
    # removing any row breaks every hash after it, and the break is findable.
    # Storage that lets an admin edit rows is exactly the case this is for.
    prev_hash = Column(String(64), nullable=False, server_default="")
    entry_hash = Column(String(64), nullable=False, server_default="")
    # Not a foreign key: the referenced finding may already be deleted, and the
    # log must still record which id it was.
    finding_id = Column(Integer, index=True)
    detail = Column(String)