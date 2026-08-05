from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
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
CLOSED_STATUSES = ("fixed", "accepted_risk")


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
    # Not a foreign key: the referenced finding may already be deleted, and the
    # log must still record which id it was.
    finding_id = Column(Integer, index=True)
    detail = Column(String)