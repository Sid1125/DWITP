from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.common.models import (
    AIClassificationOutput,
    AnalysisResult,
    AuditEvent,
    CrawlTarget,
    DiscoveredCandidate,
    IntelligenceFinding,
    RawEvidenceRecord,
    SanitizedRecord,
    SourceReputation,
)


class TestCrawlTarget:
    def test_valid_minimal(self):
        target = CrawlTarget(
            source_id="src1",
            url="http://abc.onion",
            category="malware",
            status="approved",
            approved_by="analyst1",
            approved_date="2026-01-01",
        )
        assert target.source_id == "src1"
        assert target.status == "approved"
        assert target.risk_level == "medium"
        assert target.approval_signature == ""
        assert target.review_notes == ""
        assert target.last_reviewed == ""

    def test_accepted_pending_status(self):
        target = CrawlTarget(
            source_id="s2",
            url="http://def.onion",
            category="chat",
            status="pending",
            approved_by="",
            approved_date="",
        )
        assert target.status == "pending"

    def test_accepted_retired_status(self):
        target = CrawlTarget(
            source_id="s3",
            url="http://ghi.onion",
            category="market",
            status="retired",
            approved_by="analyst2",
            approved_date="2026-03-01",
        )
        assert target.status == "retired"

    def test_accepted_quarantined_status(self):
        target = CrawlTarget(
            source_id="s4",
            url="http://jkl.onion",
            category="scam",
            status="quarantined",
            approved_by="analyst3",
            approved_date="2026-04-01",
        )
        assert target.status == "quarantined"

    def test_rejects_invalid_status(self):
        with pytest.raises(ValidationError):
            CrawlTarget(
                source_id="s5",
                url="http://mno.onion",
                category="other",
                status="invalid_status",
                approved_by="",
                approved_date="",
            )

    def test_allows_risk_level_low(self):
        target = CrawlTarget(
            source_id="s6",
            url="http://pqr.onion",
            category="forum",
            status="approved",
            approved_by="analyst",
            approved_date="2026-01-01",
            risk_level="low",
        )
        assert target.risk_level == "low"

    def test_allows_risk_level_high(self):
        target = CrawlTarget(
            source_id="s7",
            url="http://stu.onion",
            category="leak",
            status="approved",
            approved_by="analyst",
            approved_date="2026-01-01",
            risk_level="high",
        )
        assert target.risk_level == "high"

    def test_rejects_invalid_risk_level(self):
        with pytest.raises(ValidationError):
            CrawlTarget(
                source_id="s8",
                url="http://vwx.onion",
                category="forum",
                status="approved",
                approved_by="analyst",
                approved_date="2026-01-01",
                risk_level="critical",
            )

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            CrawlTarget(
                source_id="s9",
                url="http://yza.onion",
                category="forum",
                status="approved",
                approved_by="analyst",
                approved_date="2026-01-01",
                extra_field="nope",
            )

    def test_all_fields_set(self):
        target = CrawlTarget(
            source_id="s10",
            url="http://full.onion",
            category="credential_leak",
            status="approved",
            approved_by="analyst_jane",
            approved_date="2026-06-01",
            approval_signature="sig_abc123",
            risk_level="high",
            review_notes="Reviewed on 2026-06-01, all clear",
            last_reviewed="2026-06-01",
        )
        assert target.approval_signature == "sig_abc123"
        assert target.review_notes == "Reviewed on 2026-06-01, all clear"
        assert target.last_reviewed == "2026-06-01"


class TestRawEvidenceRecord:
    def test_generates_id(self):
        record = RawEvidenceRecord(
            sha256="a" * 64,
            source="test",
            url="http://abc.onion",
            raw_text="content",
        )
        assert len(record.record_id) == 32

    def test_sha256_required(self):
        with pytest.raises(ValidationError):
            RawEvidenceRecord(source="test", url="http://abc.onion", raw_text="content")

    def test_timestamp_defaults_to_now(self):
        record = RawEvidenceRecord(
            sha256="b" * 64,
            source="test",
            url="http://abc.onion",
            raw_text="content",
        )
        assert isinstance(record.timestamp_utc, datetime)
        assert record.timestamp_utc.tzinfo is not None

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            RawEvidenceRecord(
                sha256="c" * 64,
                source="test",
                url="http://abc.onion",
                raw_text="content",
                bad_extra="nope",
            )


class TestSanitizedRecord:
    def test_valid_record(self):
        record = SanitizedRecord(
            record_id="abc123",
            source="test",
            url="http://abc.onion",
            sha256="d" * 64,
            collected_at=datetime.now(timezone.utc),
            content_sanitized="clean content",
        )
        assert record.injection_patterns_detected == []

    def test_injection_patterns_defaults(self):
        record = SanitizedRecord(
            record_id="abc123",
            source="test",
            url="http://abc.onion",
            sha256="e" * 64,
            collected_at=datetime.now(timezone.utc),
            content_sanitized="<script>bad</script>",
        )
        assert record.injection_patterns_detected == []

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SanitizedRecord(
                record_id="abc123",
                source="test",
                url="http://abc.onion",
                sha256="f" * 64,
                collected_at=datetime.now(timezone.utc),
                content_sanitized="content",
                bad_extra="nope",
            )


class TestAIClassificationOutput:
    def test_valid_minimal(self):
        record = AIClassificationOutput(
            record_id="r1",
            category="ransomware",
            confidence=0.85,
            summary="This is a ransomware sample",
        )
        assert record.category == "ransomware"
        assert record.entities == {}

    def test_confidence_capped_at_one(self):
        with pytest.raises(ValidationError):
            AIClassificationOutput(
                record_id="r2",
                category="malware_sale",
                confidence=1.5,
                summary="test",
            )

    def test_confidence_min_zero(self):
        with pytest.raises(ValidationError):
            AIClassificationOutput(
                record_id="r3",
                category="scam",
                confidence=-0.1,
                summary="test",
            )

    def test_all_categories(self):
        for cat in [
            "ransomware",
            "malware_sale",
            "credential_leak",
            "access_broker",
            "data_leak",
            "scam",
            "unknown",
        ]:
            AIClassificationOutput(
                record_id="r",
                category=cat,
                confidence=0.5,
                summary="test",
            )

    def test_summary_max_length_500(self):
        with pytest.raises(ValidationError):
            AIClassificationOutput(
                record_id="r4",
                category="unknown",
                confidence=0.5,
                summary="x" * 501,
            )


class TestSourceReputation:
    def test_default_scores(self):
        sr = SourceReputation(source_name="test_src")
        assert sr.reliability_score == 0.5
        assert sr.activity_score == 0.5
        assert sr.risk_score == 0.5
        assert sr.poisoning_incidents == 0
        assert sr.status == "active"

    def test_scores_out_of_range(self):
        with pytest.raises(ValidationError):
            SourceReputation(source_name="bad", reliability_score=1.5)
        with pytest.raises(ValidationError):
            SourceReputation(source_name="bad", reliability_score=-0.1)

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SourceReputation(source_name="test", extra_field="nope")


class TestDiscoveredCandidate:
    def test_default_status(self):
        dc = DiscoveredCandidate(
            url="http://new.onion",
            discovered_from="crawler-01",
        )
        assert dc.status == "pending_review"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            DiscoveredCandidate(
                url="http://x.onion",
                discovered_from="crawler-01",
                bad_extra="nope",
            )


class TestAnalysisResult:
    def test_confidence_default(self):
        ar = AnalysisResult(
            record_id="r1",
            source="s1",
            url="http://abc.onion",
        )
        assert ar.confidence_level == "UNCONFIRMED"
        assert ar.alert_triggered is False
        assert ar.corroborating_sources == 0
        assert ar.entities["cves"] == []
        assert ar.mitre_ttps == []

    def test_mitre_ttps_can_be_set(self):
        ar = AnalysisResult(
            record_id="r1",
            source="s1",
            url="http://abc.onion",
            mitre_ttps=["T1486", "T1059"],
        )
        assert "T1486" in ar.mitre_ttps

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            AnalysisResult(
                record_id="r1",
                source="s1",
                url="http://abc.onion",
                bad_extra="nope",
            )


class TestIntelligenceFinding:
    def test_generates_finding_id(self):
        fi = IntelligenceFinding(
            record_id="r1",
            category="ransomware",
            confidence=0.9,
            source="s1",
            summary="test finding",
            raw_timestamp=datetime.now(timezone.utc),
        )
        assert len(fi.finding_id) == 32

    def test_review_defaults(self):
        fi = IntelligenceFinding(
            record_id="r1",
            category="leak",
            confidence=0.5,
            source="s1",
            summary="test",
            raw_timestamp=datetime.now(timezone.utc),
        )
        assert fi.requires_human_review is False
        assert fi.reviewed is False
        assert fi.reviewed_by is None


class TestAuditEvent:
    def test_valid_event(self):
        ae = AuditEvent(event="test_event", details={"key": "val"})
        assert ae.event == "test_event"
        assert ae.details == {"key": "val"}
        assert ae.timestamp.tzinfo is not None

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            AuditEvent(event="test", bad_extra="nope")
