"""
SQLAlchemy ORM models — 7 tables.

Each class below becomes one table in PostgreSQL.
Each attribute becomes one column.

TABLE RELATIONSHIPS:
organizations ──┬── api_keys (one org has many keys)
                ├── attack_sessions (one org has many attacks)
                └── feedback (one org has many feedback entries)

fingerprints ──── fingerprint_ips (one fingerprint has many IPs)

requests ──── standalone (uses fingerprint_hash string,
              not a foreign key, because fingerprints are
              created asynchronously by the background worker)
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    ForeignKey,
    Index,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


# V1 is single-tenant (one organization).
# This constant UUID is used everywhere instead of
# generating random ones. Every request, fingerprint,
# and attack belongs to this one organization.
DEFAULT_ORG_ID = uuid.UUID(
    "00000000-0000-0000-0000-000000000001"
)


class Base(DeclarativeBase):
    """
    Base class that all models inherit from.
    SQLAlchemy uses this to discover all your models
    and generate the right SQL for table creation.
    """
    pass


class Organization(Base):
    """
    WHO owns this Vigil instance.

    V1: Single default organization.
    V2: Multiple organizations (SaaS multi-tenancy).

    Why include it in V1? So the database schema
    supports multi-tenancy without ANY schema changes
    in V2. Only application code changes needed.
    """
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(255))
    plan: Mapped[str] = mapped_column(
        String(50), default="free"
    )
    max_requests_per_day: Mapped[int] = mapped_column(
        Integer, default=10000
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    # Relationship: one organization has many API keys
    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="organization"
    )


class ApiKey(Base):
    """
    Authentication keys for Vigil's API.

    HOW API KEY AUTH WORKS:
    1. Admin creates a key via dashboard → gets "vgl_a1b2c3d4..."
    2. We store SHA256 HASH of the key (not the key itself)
    3. Client sends key in header: X-API-Key: vgl_a1b2c3d4...
    4. We hash what they sent and look up the hash
    5. Found → authenticated. Not found → 401 Unauthorized.

    WHY HASH: If our database leaks, attackers get
    useless hashes instead of working keys.

    key_prefix: first 8 chars of the key, stored in plain
    text so admins can identify which key is which
    without revealing the full key.
    """
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
    )
    key_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
    key_prefix: Mapped[str] = mapped_column(String(8))
    name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="api_keys"
    )


class Fingerprint(Base):
    """
    Device fingerprints — a hash of HTTP signals that
    identify a client/device.

    NOT a browser fingerprint (those need JavaScript).
    This uses HTTP headers that EVERY client sends
    automatically with every request.

    WHY NOT JUST USE IP ADDRESS:
    Attackers rotate IPs using proxy networks (100s of IPs).
    But the same attacker using Python's requests library
    will always have the same:
      - User-Agent pattern
      - Accept-Encoding: "gzip, deflate"
      - sec-ch-ua: empty (Python doesn't send this)

    Even from 100 different IPs, the fingerprint catches them.

    total_requests: lifetime count of all requests
    total_blocked: how many times we blocked this fingerprint
    distinct_ip_count: number of unique IPs seen
    (high count = likely using proxy network)
    """
    __tablename__ = "fingerprints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    fingerprint_hash: Mapped[str] = mapped_column(
        String(16), unique=True, index=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    total_requests: Mapped[int] = mapped_column(
        Integer, default=0
    )
    total_blocked: Mapped[int] = mapped_column(
        Integer, default=0
    )
    distinct_ip_count: Mapped[int] = mapped_column(
        Integer, default=1
    )
    is_blocked: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    is_allowlisted: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    blocked_reason: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    blocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class FingerprintIp(Base):
    """
    Which IPs has each fingerprint used?

    Normal user: 1-3 IPs (home WiFi, office, mobile data)
    Attacker with proxy network: 50-500 IPs

    This table tracks every unique (fingerprint, IP) pair
    with counts and timestamps.

    The unique index on (fingerprint_id, ip_address) means:
    - One row per fingerprint-IP combination
    - If same fingerprint uses same IP again, we UPDATE
      the existing row (increment count, update last_seen)
    - NOT insert a duplicate
    """
    __tablename__ = "fingerprint_ips"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    fingerprint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fingerprints.id", ondelete="CASCADE"),
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(45))
    # String(45) because IPv6 addresses can be up to 45 chars
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    request_count: Mapped[int] = mapped_column(
        Integer, default=1
    )

    __table_args__ = (
        # Unique composite index: one row per (fingerprint, IP)
        Index(
            "idx_fp_ips_unique",
            "fingerprint_id",
            "ip_address",
            unique=True,
        ),
    )


class Request(Base):
    """
    EVERY request that passes through Vigil.

    This will be the LARGEST table. At 100 requests/sec,
    that's 8.6 million rows per day.

    IMPORTANT DESIGN DECISION — fingerprint_hash is a
    string, NOT a foreign key to fingerprints table:

    Why? Fingerprints are created asynchronously by the
    background worker. A request might reference a
    fingerprint_hash before the worker has created the
    corresponding row in the fingerprints table.
    If we enforced a foreign key, the request INSERT
    would fail.

    INDEXES EXPLAINED:
    Without indexes, finding "all requests from fingerprint X"
    requires scanning ALL rows (full table scan). At 1M rows,
    that's seconds. With an index, it's milliseconds.

    We create indexes on columns we frequently filter/sort by:
    - fingerprint_hash + created_at → "show me this fingerprint's recent history"
    - org_id + created_at → "show me this org's recent traffic"
    - is_suspicious + created_at → "show me recent suspicious requests"
      (partial index: only indexes rows where is_suspicious=true,
       saving space since most requests are NOT suspicious)
    """
    __tablename__ = "requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True
    )
    # The 16-char hex hash from fingerprinting
    fingerprint_hash: Mapped[str] = mapped_column(
        String(16), index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45))
    method: Mapped[str] = mapped_column(String(10))
    # String(10) is enough for GET, POST, PUT, DELETE, PATCH, etc.
    path: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    response_time_ms: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    threat_score: Mapped[float] = mapped_column(
        Float, default=0.0
    )
    # What Vigil decided: "allow", "block", "challenge", "shadowban"
    action_taken: Mapped[str] = mapped_column(
        String(20), default="allow"
    )
    is_suspicious: Mapped[bool] = mapped_column(
        Boolean, default=False
    )
    # Hash of the request body (for credential stuffing detection)
    body_hash: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    __table_args__ = (
        # Composite index: fast lookup by fingerprint + time range
        Index(
            "idx_requests_fp_time",
            "fingerprint_hash",
            "created_at",
        ),
        # Composite index: fast lookup by org + time range
        Index(
            "idx_requests_org_time",
            "org_id",
            "created_at",
        ),
        # PARTIAL index: only indexes suspicious requests.
        # Most requests are NOT suspicious, so this index
        # is tiny compared to a full index. Speeds up
        # "show me suspicious requests" queries massively.
        Index(
            "idx_requests_suspicious",
            "is_suspicious",
            "created_at",
            postgresql_where=text("is_suspicious = true"),
        ),
    )


class AttackSession(Base):
    """
    A detected attack — a group of suspicious requests
    identified as a coordinated attack campaign.

    LIFECYCLE:
    1. Background worker detects a pattern (e.g., enumeration)
    2. Worker creates an AttackSession with status="active"
    3. AI analyst fills in explanation fields
    4. Admin reviews on dashboard, marks as resolved
    5. Admin can submit feedback (true positive / false positive)

    fingerprint_hash links to the attacker's fingerprint.
    Stored as string (not FK) for the same async reason
    as the Request table.
    """
    __tablename__ = "attack_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        index=True,
    )
    # Which fingerprint is attacking
    fingerprint_hash: Mapped[str | None] = mapped_column(
        String(16), nullable=True, index=True
    )
    # "enumeration", "credential_stuffing", "brute_force", etc.
    attack_type: Mapped[str] = mapped_column(String(50))
    # "critical", "high", "medium", "low"
    severity: Mapped[str] = mapped_column(String(20))
    # "active", "mitigated", "resolved", "false_positive"
    status: Mapped[str] = mapped_column(
        String(20), default="active"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True)
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_requests: Mapped[int] = mapped_column(
        Integer, default=0
    )
    total_fingerprints: Mapped[int] = mapped_column(
        Integer, default=0
    )
    total_ips: Mapped[int] = mapped_column(
        Integer, default=0
    )
    # AI analysis stored as JSON (flexible structure)
    ai_analysis: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )
    ai_confidence: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    ai_explanation: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class Feedback(Base):
    """
    Human feedback on Vigil's detection accuracy.

    WHY THIS EXISTS:
    Without feedback, we never know our false positive rate.
    If Vigil blocks a legitimate user, they need a way to
    report it. This table tracks those reports.

    VERDICTS:
    - "true_positive" → Vigil was right, this was an attack
    - "false_positive" → Vigil was wrong, this was legitimate
    - "unknown" → reviewer isn't sure

    V2: Use accumulated feedback to auto-calibrate
    scoring weights (if certain attack types have high
    false positive rates, reduce their weight).
    """
    __tablename__ = "feedback"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
    )
    fingerprint_hash: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )
    attack_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_sessions.id"),
        nullable=True,
    )
    verdict: Mapped[str] = mapped_column(String(20))
    notes: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )