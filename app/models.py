from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, UniqueConstraint

from app.database import Base


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String)
    completed = Column(Boolean, default=False)
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