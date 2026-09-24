from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.app.config.detectors import DETECTOR_CONFIGS
from backend.app.detectors.adapter import DetectorAdapter
from backend.app.detectors.health import DetectorHealth
from backend.app.detectors.packet_flow_features import (
    DDOS_FEATURE_ORDER,
    PORT_SCAN_FEATURE_ORDER,
    PacketFlowFeatureProducer,
    select_contract_features,
)
from backend.app.detectors.registry import DetectorRegistry
from backend.app.ingestion.normalizer import normalize_zeek_record
from backend.app.ingestion.zeek_reader import iter_zeek_records
from backend.app.pipeline.ordering import ReorderBuffer, ReorderConfig
from backend.app.pipeline.orchestrator import RuntimeOrchestrator


BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
DNS53_PACKET_LOG = Path(__file__).parent / "fixtures" / "zeek" / "dns53" / "packet.log"


def packet(
    seconds: int,
    *,
    uid: str = "flow-1",
    src: str = "192.0.2.10",
    dst: str = "198.51.100.20",
    src_port: int = 12345,
    dst_port: int = 443,
    protocol: int = 6,
    payload_len: int | None = 0,
    tcp_flags: int | None = 0,
    complete: bool = False,
):
    record = {
        "event_type": "packet",
        "ts": BASE + timedelta(seconds=seconds),
        "uid": uid,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": protocol,
        "flow_complete": complete,
    }
    if payload_len is not None:
        record["payload_len"] = payload_len
    if tcp_flags is not None:
        record["tcp_flags"] = tcp_flags
    return normalize_zeek_record(record)


def sample_flow_events():
    return (
        packet(0, payload_len=100, tcp_flags=0x02),
        packet(
            1,
            src="198.51.100.20",
            dst="192.0.2.10",
            src_port=443,
            dst_port=12345,
            payload_len=50,
            tcp_flags=0x10,
        ),
        packet(2, payload_len=150, tcp_flags=0x11),
        packet(2, payload_len=None, tcp_flags=None, complete=True),
    )


def test_packet_to_flow_aggregates_exact_required_fields_and_units():
    producer = PacketFlowFeatureProducer()
    events = sample_flow_events()

    for index, event in enumerate(events[:-1]):
        assert producer.observe(event, arrival_sequence=index) is None
    result = producer.observe(events[-1], arrival_sequence=3)

    assert result is not None and result.complete
    assert result.packet_count == 3
    assert result.flow_start_at == BASE
    assert result.observed_at == BASE + timedelta(seconds=2)
    assert result.features == {
        "Flow Packets/s": 1.5,
        "Flow Bytes/s": 150.0,
        "Flow Duration": 2_000_000,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 1,
        "Fwd Packets Length Total": 250,
        "Bwd Packets Length Total": 50,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
        "ACK Flag Count": 2,
        "Packet Length Mean": 100.0,
        "Packet Length Std": 50.0,
        "Destination Port": 443,
        "Fwd Packets/s": 1.0,
        "Bwd Packets/s": 0.5,
        "FIN Flag Count": 1,
        "Protocol": 6,
    }
    assert result.provenance["source_log"] == "packet.log"
    assert result.provenance["flow_end_record"] == events[-1].raw_metadata


def test_forward_direction_uses_first_source_record_even_after_timestamp_reordering():
    producer = PacketFlowFeatureProducer()
    first_capture_packet = packet(0, payload_len=20, tcp_flags=2)
    later_capture_packet = packet(
        1,
        src="198.51.100.20",
        dst="192.0.2.10",
        src_port=443,
        dst_port=12345,
        payload_len=80,
        tcp_flags=16,
    )
    marker = packet(1, payload_len=None, tcp_flags=None, complete=True)

    # The reorder buffer may deliver the later timestamp first; original Zeek
    # packet-log order remains the direction authority.
    assert producer.observe(later_capture_packet, arrival_sequence=1) is None
    assert producer.observe(first_capture_packet, arrival_sequence=0) is None
    result = producer.observe(marker, arrival_sequence=2)

    assert result is not None and result.complete
    assert result.source_ip == "192.0.2.10"
    assert result.destination_ip == "198.51.100.20"
    assert result.source_port == 12345
    assert result.destination_port == 443
    assert result.features["Total Fwd Packets"] == 1
    assert result.features["Total Backward Packets"] == 1
    assert result.features["Fwd Packets Length Total"] == 20
    assert result.features["Bwd Packets Length Total"] == 80


def test_udp_flags_are_zero_only_when_protocol_observation_is_udp():
    producer = PacketFlowFeatureProducer()
    observation = packet(0, protocol=17, payload_len=12, tcp_flags=None)
    marker = packet(0, protocol=17, payload_len=None, tcp_flags=None, complete=True)

    producer.observe(observation, arrival_sequence=0)
    result = producer.observe(marker, arrival_sequence=1)

    assert result is not None and result.complete
    assert result.features["SYN Flag Count"] == 0
    assert result.features["RST Flag Count"] == 0
    assert result.features["ACK Flag Count"] == 0
    assert result.features["FIN Flag Count"] == 0
    assert result.features["Flow Packets/s"] == 0.0


def test_zero_duration_flow_uses_zero_rates_and_preserves_payload_features():
    producer = PacketFlowFeatureProducer()
    producer.observe(packet(0, payload_len=20, tcp_flags=0x13), arrival_sequence=0)
    result = producer.observe(
        packet(0, payload_len=None, tcp_flags=None, complete=True),
        arrival_sequence=1,
    )

    assert result is not None and result.complete
    assert result.features["Flow Duration"] == 0
    assert result.features["Flow Packets/s"] == 0.0
    assert result.features["Flow Bytes/s"] == 0.0
    assert result.features["Fwd Packets/s"] == 0.0
    assert result.features["Bwd Packets/s"] == 0.0
    assert result.features["Fwd Packets Length Total"] == 20
    assert result.features["Packet Length Mean"] == 20.0
    assert result.features["Packet Length Std"] == 0.0


def test_tcp_flag_bits_are_counted_per_observed_packet_and_udp_has_no_flags():
    producer = PacketFlowFeatureProducer()
    producer.observe(packet(0, payload_len=10, tcp_flags=0x13), arrival_sequence=0)
    producer.observe(packet(1, payload_len=10, tcp_flags=0x04), arrival_sequence=1)
    result = producer.observe(
        packet(1, payload_len=None, tcp_flags=None, complete=True),
        arrival_sequence=2,
    )

    assert result is not None and result.complete
    assert result.features["FIN Flag Count"] == 1
    assert result.features["SYN Flag Count"] == 1
    assert result.features["RST Flag Count"] == 1
    assert result.features["ACK Flag Count"] == 1

    udp_producer = PacketFlowFeatureProducer()
    udp_producer.observe(packet(0, protocol=17, payload_len=10, tcp_flags=None), arrival_sequence=0)
    udp_result = udp_producer.observe(
        packet(0, protocol=17, payload_len=None, tcp_flags=None, complete=True),
        arrival_sequence=1,
    )
    assert udp_result is not None and udp_result.complete
    assert all(udp_result.features[name] == 0 for name in (
        "SYN Flag Count", "RST Flag Count", "ACK Flag Count", "FIN Flag Count"
    ))


def test_missing_packet_length_or_tcp_flags_keeps_entire_flow_incomplete():
    for changed in (
        packet(0, payload_len=None, tcp_flags=2),
        packet(0, payload_len=10, tcp_flags=None),
    ):
        producer = PacketFlowFeatureProducer()
        producer.observe(changed, arrival_sequence=0)
        result = producer.observe(
            packet(1, payload_len=None, tcp_flags=None, complete=True),
            arrival_sequence=1,
        )

        assert result is not None
        assert result.features is None
        assert result.incomplete_reasons


def test_flow_without_zeek_end_marker_is_not_scored_on_flush():
    producer = PacketFlowFeatureProducer()
    producer.observe(packet(0, payload_len=10, tcp_flags=2), arrival_sequence=0)

    results = producer.flush()

    assert len(results) == 1
    assert results[0].features is None
    assert "flow-end marker" in results[0].incomplete_reasons[0]
    assert producer.pending_flow_count == 0


def test_contract_selection_preserves_exact_names_and_order():
    events = sample_flow_events()
    producer = PacketFlowFeatureProducer()
    for index, event in enumerate(events[:-1]):
        producer.observe(event, arrival_sequence=index)
    result = producer.observe(events[-1], arrival_sequence=3)
    assert result is not None and result.features is not None

    ddos = select_contract_features(result.features, DDOS_FEATURE_ORDER)
    port_scan = select_contract_features(result.features, PORT_SCAN_FEATURE_ORDER)

    assert tuple(ddos) == DDOS_FEATURE_ORDER
    assert tuple(port_scan) == PORT_SCAN_FEATURE_ORDER
    assert DDOS_FEATURE_ORDER == tuple(DETECTOR_CONFIGS["ddos"].required_features)
    assert PORT_SCAN_FEATURE_ORDER == tuple(DETECTOR_CONFIGS["port_scan"].required_features)
    assert select_contract_features({}, DDOS_FEATURE_ORDER) is None
    assert select_contract_features({}, PORT_SCAN_FEATURE_ORDER) is None


def test_real_dns53_packet_log_is_feature_pipeline_sanity_only():
    producer = PacketFlowFeatureProducer()
    records = list(iter_zeek_records(DNS53_PACKET_LOG))
    assert len(records) == 2
    packet_events = [normalize_zeek_record(record) for record in records]

    assert producer.observe(packet_events[0], arrival_sequence=0) is None
    result = producer.observe(packet_events[1], arrival_sequence=1)

    assert result is not None and result.complete
    assert result.packet_count == 1
    assert result.protocol == 17
    assert result.destination_port == 53
    assert result.features["Flow Duration"] == 0
    assert result.features["Total Fwd Packets"] == 1
    assert result.features["Total Backward Packets"] == 0
    assert result.features["Fwd Packets Length Total"] == 433
    assert result.features["Flow Packets/s"] == 0.0
    # The fixture is used only by the producer; neither model is invoked here.


class RecordingModel:
    def __init__(self, detector_name: str) -> None:
        self.detector_name = detector_name
        self.calls: list[dict[str, object]] = []

    def predict_flow(self, features):
        self.calls.append(dict(features))
        return {
            "status": "DETECTED",
            "threat_class": self.detector_name,
            "score_type": "model_score",
            "raw_score": 0.73,
            "threshold": DETECTOR_CONFIGS[
                "ddos" if self.detector_name == "ddos" else "port_scan"
            ].threshold,
            "evidence": dict(features),
            "context": {"feature_count": len(features)},
        }


def test_orchestrator_invokes_only_complete_contracts_and_keeps_score_uncalibrated():
    registry = DetectorRegistry()
    implementations = {"ddos": RecordingModel("ddos"), "portscan": RecordingModel("portscan")}
    health = {}
    for key, config_key in (("ddos", "ddos"), ("portscan", "port_scan")):
        config = DETECTOR_CONFIGS[config_key]
        implementation = implementations[key]
        adapter = DetectorAdapter(implementation, config)
        registry.register(adapter)
        health[adapter.detector_name] = DetectorHealth(
            detector_name=adapter.detector_name,
            registered=True,
            artifact_present=True,
            artifact_loadable=True,
            dependency_available=True,
            ready_for_inference=True,
        )

    orchestrator = RuntimeOrchestrator(
        ordering=ReorderBuffer(ReorderConfig(timedelta(0), 32)),
        windows=None,
        registry=registry,
        health=health,
        packet_flow_features=PacketFlowFeatureProducer(),
    )
    emitted = []
    for index, event in enumerate(sample_flow_events()):
        emitted.extend(orchestrator.process_event(event, event_id=f"packet.log:{index}"))

    assert len(implementations["ddos"].calls) == 1
    assert len(implementations["portscan"].calls) == 1
    assert tuple(implementations["ddos"].calls[0]) == DDOS_FEATURE_ORDER
    assert tuple(implementations["portscan"].calls[0]) == PORT_SCAN_FEATURE_ORDER
    assert len(emitted) == 2
    assert all(alert.score_type == "model_score" for alert in emitted)
    assert all(alert.raw_model_score == 0.73 for alert in emitted)
    assert all(alert.confidence is None for alert in emitted)
    assert all(alert.raw_model_probability is None for alert in emitted)
    assert all(alert.calibrated_confidence is None for alert in emitted)
    assert all(alert.feature_provenance["flow_uid"] == "flow-1" for alert in emitted)


def test_incomplete_flow_does_not_invoke_any_detector():
    registry = DetectorRegistry()
    implementations = {"ddos": RecordingModel("ddos"), "portscan": RecordingModel("portscan")}
    health = {}
    for key, config_key in (("ddos", "ddos"), ("portscan", "port_scan")):
        adapter = DetectorAdapter(implementations[key], DETECTOR_CONFIGS[config_key])
        registry.register(adapter)
        health[adapter.detector_name] = DetectorHealth(
            detector_name=adapter.detector_name,
            registered=True,
            artifact_present=True,
            artifact_loadable=True,
            dependency_available=True,
            ready_for_inference=True,
        )
    orchestrator = RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(0), 32)),
        None,
        registry,
        health,
        packet_flow_features=PacketFlowFeatureProducer(),
    )

    orchestrator.process_event(packet(0, payload_len=None, tcp_flags=2), "packet.log:0")
    orchestrator.process_event(
        packet(0, payload_len=None, tcp_flags=None, complete=True), "packet.log:1"
    )

    assert implementations["ddos"].calls == []
    assert implementations["portscan"].calls == []
    assert orchestrator.get_metrics()["detector_invocations"] == 0
    failures = orchestrator.get_runtime_state()["runtime_failures"]
    assert len(failures) == 2
    assert all("incomplete" in item["reason"] for item in failures)
