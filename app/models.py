from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)

from app.database import Base

# Remediation window per severity, in days. A finding without an explicit due
# date gets one from here, so nothing lands in the list without a deadline.
SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}

# Both close a finding, but not the same way: one removes the problem, the
# other keeps it and records that someone decided to live with it.
ACCEPTED_RISK = "accepted_risk"
CLOSED_STATUSES = ("fixed", ACCEPTED_RISK)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The longest a risk may be accepted for. Not a limit for its own sake: an
# acceptance that never expires is how risk accumulates — someone says "for
# now" and nobody looks again.
MAX_ACCEPTANCE_DAYS = 90

# Short enough to write, long enough that "ok" does not pass for an argument.
MIN_ACCEPTANCE_REASON = 15


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

    # What the source last rated this, as opposed to what the row now says.
    # Keeping the two apart is what lets a re-run tell "the evidence got worse"
    # (the source's rating rose) from "a person disagreed with the tool" (the
    # source is saying exactly what it said last time). Only the first is a
    # reason to overwrite a human's severity.
    source_severity = Column(String(10), nullable=False, server_default="")
    owner_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        # The lookup an import does for every incoming result.
        Index("ix_findings_dedupe", "owner_id", "asset", "source_ref"),
    )


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