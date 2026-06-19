from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class CrawlTarget(BaseModel):
    source_id: str
    url: str
    category: str
    status: Literal["approved", "pending", "retired", "quarantined"]
    approved_by: str
    approved_date: str
    approval_signature: str = ""
    risk_level: Literal["low", "medium", "high"] = "medium"
    review_notes: str = ""
    last_reviewed: str = ""
    max_pages: int = 5
    link_selector: str = ""
    queue_wait_seconds: int = 0
    # Comma-separated URL substrings that mark "listing" pages (forum boards,
    # indexes) which must be re-fetched every cycle to surface new posts. The
    # source root is always treated as a listing. Everything else is crawl-once.
    listing_patterns: str = ""

    class Config:
        extra = "forbid"


class RawEvidenceRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    sha256: str
    timestamp_utc: datetime = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    source: str
    url: str
    raw_text: str

    class Config:
        extra = "forbid"


class SanitizedRecord(BaseModel):
    record_id: str
    source: str
    url: str
    sha256: str
    collected_at: datetime
    content_sanitized: str
    injection_patterns_detected: list[str] = Field(default_factory=list)
    sanitized_at: datetime = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))

    class Config:
        extra = "forbid"


class AIClassificationOutput(BaseModel):
    record_id: Optional[str] = None
    category: Literal[
        "ransomware", "malware_sale", "credential_leak",
        "access_broker", "data_leak", "scam",
        "drug_trafficking", "weapons_trafficking",
        "terrorism_extremism", "human_trafficking",
        "unknown"
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    entities: dict = Field(default_factory=dict)
    summary: str = Field(max_length=500)
    evidence_quote: str = Field(default="", max_length=300)

    class Config:
        extra = "forbid"


class SourceReputation(BaseModel):
    source_name: str
    reliability_score: float = Field(default=0.5, ge=0.0, le=1.0)
    activity_score: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.5, ge=0.0, le=1.0)
    last_seen: datetime = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    poisoning_incidents: int = Field(default=0, ge=0)
    status: Literal["active", "degraded", "quarantined", "retired"] = "active"

    class Config:
        extra = "forbid"


class DiscoveredCandidate(BaseModel):
    url: str
    discovered_from: str
    discovered_at: datetime = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    status: Literal["pending_review", "approved", "rejected"] = "pending_review"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    class Config:
        extra = "forbid"


class AnalysisResult(BaseModel):
    record_id: str
    source: str
    url: str
    title: str = ""
    author: Optional[str] = None
    timestamp_posted: Optional[datetime] = None
    entities: dict = Field(default_factory=lambda: {
        "cves": [],
        "btc_addresses": [],
        "xmr_addresses": [],
        "eth_addresses": [],
        "email_addresses": [],
        "domains": [],
        "ip_addresses": [],
        "pgp_fingerprints": [],
        "telegram_handles": [],
        "jabber_ids": [],
        "onion_addresses": [],
    })
    classification: Optional[AIClassificationOutput] = None
    corroborating_sources: int = 0
    confidence_level: Literal["UNCONFIRMED", "LOW", "MEDIUM", "HIGH", "VERIFIED"] = "UNCONFIRMED"
    alert_triggered: bool = False
    mitre_ttps: list[str] = Field(default_factory=list)

    class Config:
        extra = "forbid"


class IntelligenceFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    record_id: str
    category: str
    confidence: float
    source: str
    summary: str
    raw_timestamp: datetime
    requires_human_review: bool = False
    reviewed: bool = False
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    class Config:
        extra = "forbid"


class AuditEvent(BaseModel):
    event: str
    timestamp: datetime = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    severity: str = "INFO"
    component: str = ""
    details: dict = Field(default_factory=dict)

    class Config:
        extra = "forbid"
