"""Unit tests for Phase 4 Deterministic Risk Engine and Anomaly Detection."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from app.models.enums import FindingStatus, Protocol, Severity
from app.services.risk_engine.anomaly_detector import (
    BaselineAnomalyDetector,
    MIN_EVENTS_FOR_BASELINE,
)
from app.services.risk_engine.calculator import (
    ANOMALY_WEIGHT,
    EXPOSURE_WEIGHT,
    RiskCalculator,
    SEVERITY_VALUES,
    VULNERABILITY_WEIGHT,
)
from app.services.risk_engine.exposure import ExposureAnalyzer, PORT_EXPOSURE_WEIGHTS
from app.services.risk_engine.finding_aggregator import FindingAggregator
from app.services.risk_engine.models import (
    BaselineStatus,
    DeviceRiskResult,
    EvaluatedFinding,
    FindingCategory,
    FindingEvidence,
    NetworkPostureResult,
)


class MockPort:
    def __init__(self, port_number: int, protocol: str = "TCP", service_name: str = "unknown"):
        self.port_number = port_number
        self.protocol = protocol
        self.service_name = service_name


class MockEvent:
    def __init__(
        self,
        destination_ip: str = "192.168.1.1",
        destination_port: int = 443,
        protocol: str = "TCP",
        event_timestamp: datetime = None,
        is_anomaly: bool = False,
    ):
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.event_timestamp = event_timestamp or datetime.now(timezone.utc)
        self.is_anomaly = is_anomaly


class MockFinding:
    def __init__(self, title: str, severity: Severity, category: str = "EXPOSURE"):
        self.title = title
        self.severity = severity
        self.category = category
        self.description = f"Description for {title}"
        self.remediation_steps = "Follow standard remediation."
        self.cve_id = ""


# ==============================================================================
# RISK CALCULATION TESTS
# ==============================================================================

def test_1_empty_device_zero_risk():
    """Verify an empty device with 0 ports, findings, or events gets 0 risk."""
    dev_id = uuid.uuid4()
    result = RiskCalculator.calculate_device_risk(device_id=dev_id)
    assert result.overall_score == 0.0
    assert result.exposure_subscore == 0.0
    assert result.vulnerability_subscore == 0.0
    assert result.anomaly_subscore == 0.0
    assert result.critical_findings_count == 0
    assert result.high_findings_count == 0
    assert result.open_risky_ports_count == 0


def test_2_device_with_http():
    """Verify device with open port 80 triggers HTTP exposure finding and expected score."""
    dev_id = uuid.uuid4()
    ports = [MockPort(80, "TCP", "http")]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    assert result.exposure_subscore == 15.0
    assert result.open_risky_ports_count == 1
    assert any("HTTP" in f.title for f in result.findings)
    assert result.overall_score > 0.0


def test_3_device_with_https():
    """Verify device with open port 443 gets low exposure score (5.0)."""
    dev_id = uuid.uuid4()
    ports = [MockPort(443, "TCP", "https")]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    assert result.exposure_subscore == 5.0
    assert result.open_risky_ports_count == 0


def test_4_device_with_ssh():
    """Verify device with open port 22 triggers SSH exposure finding and 20.0 exposure score."""
    dev_id = uuid.uuid4()
    ports = [MockPort(22, "TCP", "ssh")]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    assert result.exposure_subscore == 20.0
    assert result.open_risky_ports_count == 1
    assert any("SSH" in f.title for f in result.findings)


def test_5_device_with_smb():
    """Verify device with open port 445 triggers SMB HIGH severity finding and 35.0 exposure score."""
    dev_id = uuid.uuid4()
    ports = [MockPort(445, "TCP", "smb")]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    assert result.exposure_subscore == 35.0
    assert result.open_risky_ports_count == 1
    assert any("SMB" in f.title and f.severity == Severity.HIGH for f in result.findings)
    assert result.high_findings_count >= 1


def test_6_device_with_rtsp():
    """Verify device with open port 554 triggers RTSP media stream finding."""
    dev_id = uuid.uuid4()
    ports = [MockPort(554, "TCP", "rtsp")]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    assert result.exposure_subscore == 20.0
    assert any("RTSP" in f.title for f in result.findings)


def test_7_multiple_services_cumulative():
    """Verify multiple open ports produce cumulative exposure without duplicate counting."""
    dev_id = uuid.uuid4()
    ports = [MockPort(80), MockPort(443), MockPort(22), MockPort(445)]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    expected_exposure = 15.0 + 5.0 + 20.0 + 35.0  # 75.0
    assert result.exposure_subscore == expected_exposure
    assert result.open_risky_ports_count == 3  # 80, 22, 445


def test_8_multiple_findings_sublinear():
    """Verify multiple security findings accumulate deterministically."""
    findings = [
        MockFinding("Vuln 1", Severity.HIGH),
        MockFinding("Vuln 2", Severity.MEDIUM),
        MockFinding("Vuln 3", Severity.LOW),
    ]
    res = RiskCalculator.calculate_vulnerability_subscore(findings)
    # Base: 70.0 (HIGH), secondary: (45.0 + 20.0) * 0.15 = 9.75 -> 79.75
    assert res.vulnerability_score == 79.75
    assert res.findings_count == 3
    assert res.high_count == 1


def test_9_critical_finding_scoring():
    """Verify a critical finding produces a 95.0 base vulnerability score."""
    findings = [MockFinding("Critical RCE", Severity.CRITICAL)]
    res = RiskCalculator.calculate_vulnerability_subscore(findings)
    assert res.vulnerability_score == 95.0
    assert res.critical_count == 1


def test_10_high_finding_scoring():
    """Verify a single high finding produces a 70.0 base vulnerability score."""
    findings = [MockFinding("High Severity Issue", Severity.HIGH)]
    res = RiskCalculator.calculate_vulnerability_subscore(findings)
    assert res.vulnerability_score == 70.0
    assert res.high_count == 1


def test_11_score_bounds_and_clamping():
    """Verify risk scores never exceed 100.0 even under extreme conditions."""
    dev_id = uuid.uuid4()
    many_ports = [MockPort(p) for p in range(1, 100)]
    many_findings = [MockFinding(f"Crit {i}", Severity.CRITICAL) for i in range(20)]
    many_events = [MockEvent(destination_port=p, is_anomaly=True) for p in range(100, 150)]

    result = RiskCalculator.calculate_device_risk(
        device_id=dev_id,
        open_ports=many_ports,
        events=many_events,
        existing_findings=many_findings,
    )

    assert 0.0 <= result.overall_score <= 100.0
    assert 0.0 <= result.exposure_subscore <= 100.0
    assert 0.0 <= result.vulnerability_subscore <= 100.0
    assert 0.0 <= result.anomaly_subscore <= 100.0


def test_12_deterministic_repeatability():
    """Verify identical inputs yield identical risk outputs down to exact float precision."""
    dev_id = uuid.uuid4()
    ports = [MockPort(80), MockPort(445)]
    events = [MockEvent() for _ in range(10)]

    r1 = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports, events=events)
    r2 = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports, events=events)

    assert r1.overall_score == r2.overall_score
    assert r1.exposure_subscore == r2.exposure_subscore
    assert r1.vulnerability_subscore == r2.vulnerability_subscore
    assert r1.anomaly_subscore == r2.anomaly_subscore


def test_13_score_breakdown_structure():
    """Verify score breakdown contains correct weights and weighted contributions."""
    dev_id = uuid.uuid4()
    ports = [MockPort(80)]
    result = RiskCalculator.calculate_device_risk(device_id=dev_id, open_ports=ports)

    breakdown = result.score_breakdown
    assert "exposure" in breakdown
    assert "vulnerability" in breakdown
    assert "anomaly" in breakdown
    assert breakdown["exposure"]["weight"] == EXPOSURE_WEIGHT
    assert breakdown["vulnerability"]["weight"] == VULNERABILITY_WEIGHT
    assert breakdown["anomaly"]["weight"] == ANOMALY_WEIGHT
    assert "weighted_contribution" in breakdown["exposure"]


# ==============================================================================
# ANOMALY DETECTION TESTS
# ==============================================================================

def test_14_anomaly_insufficient_data():
    """Verify <5 events returns status 'insufficient_data' with score 0.0."""
    events = [MockEvent() for _ in range(3)]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert res.status == BaselineStatus.INSUFFICIENT_DATA
    assert res.anomaly_score == 0.0
    assert res.events_analyzed == 3


def test_15_anomaly_normal_baseline():
    """Verify standard benign HTTPS and DNS events over time produce normal status."""
    now = datetime.now(timezone.utc)
    events = [
        MockEvent(destination_port=443, event_timestamp=now - timedelta(minutes=i * 2))
        for i in range(10)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert res.status == BaselineStatus.NORMAL
    assert res.anomaly_score <= 20.0


def test_16_anomaly_elevated_traffic():
    """Verify sudden high frequency event bursts trigger elevated or anomalous status."""
    now = datetime.now(timezone.utc)
    # 20 events within 1 second
    events = [
        MockEvent(destination_port=443, event_timestamp=now - timedelta(milliseconds=i * 50))
        for i in range(20)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert res.anomaly_score > 20.0
    assert any(a["type"] == "elevated_event_rate" for a in res.anomalies_detected)


def test_17_anomaly_repeated_destination():
    """Verify high concentration (>80%) of traffic to a single destination triggers repeated_destination."""
    now = datetime.now(timezone.utc)
    events = [
        MockEvent(destination_ip="198.51.100.44", destination_port=443, event_timestamp=now - timedelta(minutes=i))
        for i in range(10)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert any(a["type"] == "repeated_destination" for a in res.anomalies_detected)
    assert res.anomaly_score >= 25.0


def test_18_anomaly_unusual_port():
    """Verify telemetry targeting multiple non-standard ports triggers port sweep / unusual ports anomaly."""
    now = datetime.now(timezone.utc)
    ports = [31337, 4444, 9999, 1337, 6667, 12345]
    events = [
        MockEvent(destination_port=p, event_timestamp=now - timedelta(minutes=i))
        for i, p in enumerate(ports)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert any(a["type"] == "port_sweep_indicator" for a in res.anomalies_detected)
    assert res.anomaly_score >= 35.0


def test_19_anomaly_protocol_deviation():
    """Verify unusual protocol events trigger protocol deviation anomaly."""
    now = datetime.now(timezone.utc)
    events = [
        MockEvent(protocol="RAW", event_timestamp=now - timedelta(minutes=i))
        for i in range(6)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert any(a["type"] == "protocol_deviation" for a in res.anomalies_detected)


def test_20_anomaly_event_rate_anomaly():
    """Verify event burst calculation accurately identifies sudden rate increase."""
    now = datetime.now(timezone.utc)
    events = [
        MockEvent(event_timestamp=now - timedelta(seconds=i))
        for i in range(10)
    ]
    res = BaselineAnomalyDetector.detect_anomalies(events)
    assert res.baseline.current_event_rate > 0.0


# ==============================================================================
# FINDING AGGREGATION TESTS
# ==============================================================================

def test_21_http_exposure_finding():
    """Verify HTTP port 80 generates an EXPOSURE finding with evidence."""
    dev_id = uuid.uuid4()
    findings = FindingAggregator.generate_findings_from_ports(dev_id, [80])
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.EXPOSURE.value
    assert f.severity == Severity.MEDIUM
    assert f.evidence["port"] == 80


def test_22_smb_exposure_finding():
    """Verify SMB port 445 generates an EXPOSURE finding with HIGH severity."""
    dev_id = uuid.uuid4()
    findings = FindingAggregator.generate_findings_from_ports(dev_id, [445])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence["port"] == 445


def test_23_rtsp_exposure_finding():
    """Verify RTSP port 554 generates a media stream EXPOSURE finding."""
    dev_id = uuid.uuid4()
    findings = FindingAggregator.generate_findings_from_ports(dev_id, [554])
    assert len(findings) == 1
    f = findings[0]
    assert "RTSP" in f.title


def test_24_evidence_generation():
    """Verify evidence schema is strictly populated with source, port, protocol, reason."""
    evidence = FindingEvidence(
        source="open_port",
        port=445,
        protocol="TCP",
        reason="SMB service observed",
    )
    assert evidence.source == "open_port"
    assert evidence.port == 445
    assert evidence.protocol == "TCP"
    assert evidence.reason == "SMB service observed"


def test_25_no_finding_without_evidence():
    """Verify all generated findings contain non-empty evidence."""
    dev_id = uuid.uuid4()
    findings = FindingAggregator.generate_findings_from_ports(dev_id, [22, 80, 445, 554, 8080])
    assert len(findings) == 5
    for f in findings:
        assert bool(f.evidence) is True
        assert "source" in f.evidence
        assert "reason" in f.evidence

