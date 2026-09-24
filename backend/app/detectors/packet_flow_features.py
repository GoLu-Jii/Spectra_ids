from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from math import sqrt
from typing import Any, Mapping

from ..ingestion.events import NormalizedEvent


DDOS_FEATURE_ORDER = (
    "Flow Packets/s",
    "Flow Bytes/s",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Packet Length Std",
    "Protocol",
)

PORT_SCAN_FEATURE_ORDER = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "FIN Flag Count",
)

_FLAG_MASKS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "ACK": 0x10}


@dataclass(frozen=True)
class CompletedFlowFeatures:
    """One closed Zeek connection with packet-derived, complete model inputs."""

    flow_id: str | None
    observed_at: datetime
    flow_start_at: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    packet_count: int
    features: dict[str, int | float] | None
    incomplete_reasons: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return self.features is not None


@dataclass
class _FlowAccumulator:
    flow_id: str
    start_at: datetime
    end_at: datetime
    first_sequence: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    packets: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_payload_bytes: int = 0
    bwd_payload_bytes: int = 0
    packet_length_mean: float = 0.0
    packet_length_m2: float = 0.0
    tcp_flags: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in _FLAG_MASKS}
    )
    incomplete_reasons: list[str] = field(default_factory=list)

    def mark_incomplete(self, reason: str) -> None:
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)


class PacketFlowFeatureProducer:
    """Aggregate Zeek ``new_packet`` observations until its flow-end marker.

    Forward is the source endpoint of the first packet emitted in that Zeek
    packet log. ``arrival_sequence`` preserves that source order even when
    SPECTRA releases other events out of timestamp order.
    """

    def __init__(self) -> None:
        self._flows: dict[str, _FlowAccumulator] = {}
        self._invalid_flows: dict[str, list[str]] = {}

    @property
    def pending_flow_count(self) -> int:
        return len(self._flows) + len(self._invalid_flows)

    def observe(
        self, event: NormalizedEvent, *, arrival_sequence: int
    ) -> CompletedFlowFeatures | None:
        """Consume one packet.log event; return a result only at flow end."""
        if event.event_type.lower() != "packet":
            return None

        record = event.raw_metadata
        flow_id = _text(record.get("uid") or record.get("flow_id") or event.flow_id)
        if flow_id is None:
            return self._incomplete_result(
                None, event, "packet observation is missing Zeek connection uid"
            )

        marker_value = record.get("flow_complete")
        is_complete, completion_error = _flow_complete(marker_value)
        if marker_value is None or marker_value == "" or completion_error:
            reason = completion_error or "packet observation is missing flow_complete marker"
            accumulator = self._flows.pop(flow_id, None)
            if accumulator is not None:
                self._flows[flow_id] = accumulator
                accumulator.mark_incomplete(reason)
            else:
                self._invalid_flows.setdefault(flow_id, []).append(reason)
            return self._incomplete_result(flow_id, event, reason)

        if is_complete:
            accumulator = self._flows.pop(flow_id, None)
            if accumulator is None:
                prior_errors = self._invalid_flows.pop(flow_id, [])
                if prior_errors:
                    return self._incomplete_result(
                        flow_id, event, "; ".join(dict.fromkeys(prior_errors))
                    )
                return self._incomplete_result(
                    flow_id, event, "flow-end marker has no packet observations"
                )
            self._check_completion_identity(accumulator, record)
            return self._finish(accumulator, event, record)

        if flow_id in self._invalid_flows:
            return None

        accumulator = self._flows.get(flow_id)
        if accumulator is None:
            accumulator, reason = self._new_accumulator(flow_id, event, arrival_sequence)
            if accumulator is None:
                self._invalid_flows[flow_id] = [reason or "invalid packet"]
                return self._incomplete_result(flow_id, event, reason or "invalid packet")
            self._flows[flow_id] = accumulator

        self._add_packet(accumulator, event, arrival_sequence)
        return None

    def flush(self) -> tuple[CompletedFlowFeatures, ...]:
        """Return incomplete results for flows that never got a Zeek end marker."""
        pending = tuple(self._flows.values())
        self._flows.clear()
        self._invalid_flows = {}
        results: list[CompletedFlowFeatures] = []
        for accumulator in pending:
            accumulator.mark_incomplete("Zeek flow-end marker was not observed")
            results.append(
                CompletedFlowFeatures(
                    flow_id=accumulator.flow_id,
                    observed_at=accumulator.end_at,
                    flow_start_at=accumulator.start_at,
                    source_ip=accumulator.source_ip,
                    destination_ip=accumulator.destination_ip,
                    source_port=accumulator.source_port,
                    destination_port=accumulator.destination_port,
                    protocol=accumulator.protocol,
                    packet_count=accumulator.packets,
                    features=None,
                    incomplete_reasons=tuple(accumulator.incomplete_reasons),
                    provenance={
                        "producer": "zeek_new_packet_v1",
                        "flow_uid": accumulator.flow_id,
                        "packet_observations": accumulator.packets,
                        "flow_end_observed": False,
                    },
                )
            )
        return tuple(results)

    def _new_accumulator(
        self, flow_id: str, event: NormalizedEvent, arrival_sequence: int
    ) -> tuple[_FlowAccumulator | None, str | None]:
        record = event.raw_metadata
        try:
            source_ip = _required_text(record, "src")
            destination_ip = _required_text(record, "dst")
            source_port = _required_int(record, "src_port")
            destination_port = _required_int(record, "dst_port")
            protocol = _required_int(record, "proto")
        except ValueError as exc:
            return None, str(exc)
        if protocol not in (6, 17):
            return None, f"unsupported IP protocol {protocol}; TCP/UDP required"
        if (source_ip, source_port, destination_ip, destination_port) == (
            destination_ip,
            destination_port,
            source_ip,
            source_port,
        ):
            return None, "packet endpoints do not distinguish forward from backward"
        return (
            _FlowAccumulator(
                flow_id=flow_id,
                start_at=event.observed_at,
                end_at=event.observed_at,
                first_sequence=arrival_sequence,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
            ),
            None,
        )

    def _add_packet(
        self,
        accumulator: _FlowAccumulator,
        event: NormalizedEvent,
        arrival_sequence: int,
    ) -> None:
        record = event.raw_metadata
        try:
            source_ip = _required_text(record, "src")
            destination_ip = _required_text(record, "dst")
            source_port = _required_int(record, "src_port")
            destination_port = _required_int(record, "dst_port")
            protocol = _required_int(record, "proto")
            payload_length = _required_int(record, "payload_len")
        except ValueError as exc:
            accumulator.mark_incomplete(str(exc))
            return

        if payload_length < 0:
            accumulator.mark_incomplete("payload_len must not be negative")
            return
        if protocol != accumulator.protocol:
            accumulator.mark_incomplete("IP protocol changed within Zeek connection uid")
            return

        current_forward = (
            accumulator.source_ip,
            accumulator.source_port,
            accumulator.destination_ip,
            accumulator.destination_port,
        )
        packet_tuple = (source_ip, source_port, destination_ip, destination_port)
        reverse_tuple = (
            accumulator.destination_ip,
            accumulator.destination_port,
            accumulator.source_ip,
            accumulator.source_port,
        )
        if packet_tuple not in (current_forward, reverse_tuple):
            accumulator.mark_incomplete("packet endpoints changed within Zeek connection uid")
            return

        if arrival_sequence < accumulator.first_sequence:
            accumulator.source_ip = source_ip
            accumulator.source_port = source_port
            accumulator.destination_ip = destination_ip
            accumulator.destination_port = destination_port
            accumulator.first_sequence = arrival_sequence
            accumulator.fwd_packets, accumulator.bwd_packets = (
                accumulator.bwd_packets,
                accumulator.fwd_packets,
            )
            accumulator.fwd_payload_bytes, accumulator.bwd_payload_bytes = (
                accumulator.bwd_payload_bytes,
                accumulator.fwd_payload_bytes,
            )

        forward_tuple = (
            accumulator.source_ip,
            accumulator.source_port,
            accumulator.destination_ip,
            accumulator.destination_port,
        )
        is_forward = packet_tuple == forward_tuple

        if event.observed_at < accumulator.start_at:
            accumulator.start_at = event.observed_at
        if event.observed_at > accumulator.end_at:
            accumulator.end_at = event.observed_at

        accumulator.packets += 1
        if is_forward:
            accumulator.fwd_packets += 1
            accumulator.fwd_payload_bytes += payload_length
        else:
            accumulator.bwd_packets += 1
            accumulator.bwd_payload_bytes += payload_length

        # CICFlowMeter packet-length features use transport payload bytes.
        count = accumulator.packets
        delta = payload_length - accumulator.packet_length_mean
        accumulator.packet_length_mean += delta / count
        accumulator.packet_length_m2 += delta * (
            payload_length - accumulator.packet_length_mean
        )

        if protocol == 6:
            try:
                flags = _required_int(record, "tcp_flags")
            except ValueError as exc:
                accumulator.mark_incomplete(str(exc))
            else:
                for name, mask in _FLAG_MASKS.items():
                    accumulator.tcp_flags[name] += int(bool(flags & mask))
        # CICFlowMeter records no TCP flags for UDP; zero is structurally exact.

    def _check_completion_identity(
        self, accumulator: _FlowAccumulator, record: Mapping[str, Any]
    ) -> None:
        checks = (
            ("src", accumulator.source_ip),
            ("dst", accumulator.destination_ip),
            ("src_port", accumulator.source_port),
            ("dst_port", accumulator.destination_port),
            ("proto", accumulator.protocol),
        )
        for field_name, expected in checks:
            value = record.get(field_name)
            if value is None or value == "-" or value == "":
                continue
            try:
                parsed = _int_value(value) if field_name.endswith("port") or field_name == "proto" else str(value)
            except ValueError:
                accumulator.mark_incomplete(f"flow-end marker has invalid {field_name}")
                continue
            if parsed != expected:
                accumulator.mark_incomplete(
                    f"flow-end marker {field_name} does not match first packet direction"
                )

    def _finish(
        self,
        accumulator: _FlowAccumulator,
        event: NormalizedEvent,
        record: Mapping[str, Any],
    ) -> CompletedFlowFeatures:
        features: dict[str, int | float] | None = None
        if not accumulator.incomplete_reasons:
            duration = accumulator.end_at - accumulator.start_at
            duration_us = max(
                0,
                (duration.days * 86_400 + duration.seconds) * 1_000_000
                + duration.microseconds,
            )
            duration_seconds = duration_us / 1_000_000
            total_packets = accumulator.fwd_packets + accumulator.bwd_packets
            total_payload_bytes = (
                accumulator.fwd_payload_bytes + accumulator.bwd_payload_bytes
            )
            if duration_seconds > 0:
                packet_rate = total_packets / duration_seconds
                byte_rate = total_payload_bytes / duration_seconds
                fwd_packet_rate = accumulator.fwd_packets / duration_seconds
                bwd_packet_rate = accumulator.bwd_packets / duration_seconds
            else:
                # CICFlowMeter defines rates as zero for a zero-duration flow.
                packet_rate = byte_rate = fwd_packet_rate = bwd_packet_rate = 0.0
            packet_std = (
                sqrt(accumulator.packet_length_m2 / (accumulator.packets - 1))
                if accumulator.packets > 1
                else 0.0
            )
            features = {
                "Flow Packets/s": packet_rate,
                "Flow Bytes/s": byte_rate,
                "Flow Duration": duration_us,
                "Total Fwd Packets": accumulator.fwd_packets,
                "Total Backward Packets": accumulator.bwd_packets,
                "Fwd Packets Length Total": accumulator.fwd_payload_bytes,
                "Bwd Packets Length Total": accumulator.bwd_payload_bytes,
                "SYN Flag Count": accumulator.tcp_flags["SYN"],
                "RST Flag Count": accumulator.tcp_flags["RST"],
                "ACK Flag Count": accumulator.tcp_flags["ACK"],
                "Packet Length Mean": accumulator.packet_length_mean,
                "Packet Length Std": packet_std,
                "Destination Port": accumulator.destination_port,
                "Fwd Packets/s": fwd_packet_rate,
                "Bwd Packets/s": bwd_packet_rate,
                "FIN Flag Count": accumulator.tcp_flags["FIN"],
                "Protocol": accumulator.protocol,
            }

        return CompletedFlowFeatures(
            flow_id=accumulator.flow_id,
            observed_at=event.observed_at,
            flow_start_at=accumulator.start_at,
            source_ip=accumulator.source_ip,
            destination_ip=accumulator.destination_ip,
            source_port=accumulator.source_port,
            destination_port=accumulator.destination_port,
            protocol=accumulator.protocol,
            packet_count=accumulator.packets,
            features=features,
            incomplete_reasons=tuple(accumulator.incomplete_reasons),
            provenance={
                "producer": "zeek_new_packet_v1",
                "source_log": "packet.log",
                "flow_uid": accumulator.flow_id,
                "packet_observations": accumulator.packets,
                "direction_rule": "source endpoint of first Zeek packet-log observation is forward",
                "flow_end_observed": True,
                "flow_end_record": dict(record),
            },
        )

    @staticmethod
    def _incomplete_result(
        flow_id: str | None, event: NormalizedEvent, reason: str
    ) -> CompletedFlowFeatures:
        return CompletedFlowFeatures(
            flow_id=flow_id,
            observed_at=event.observed_at,
            flow_start_at=None,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=None,
            packet_count=0,
            features=None,
            incomplete_reasons=(reason,),
            provenance={"producer": "zeek_new_packet_v1", "flow_uid": flow_id},
        )


def select_contract_features(
    features: Mapping[str, int | float], required_fields: tuple[str, ...] | list[str]
) -> dict[str, int | float] | None:
    """Select a detector's exact declared field set and order, or no vector."""
    if any(name not in features for name in required_fields):
        return None
    return {name: features[name] for name in required_fields}


def _required_text(record: Mapping[str, Any], name: str) -> str:
    value = record.get(name)
    if value is None or value == "-" or value == "":
        raise ValueError(f"packet observation is missing {name}")
    return str(value)


def _required_int(record: Mapping[str, Any], name: str) -> int:
    value = record.get(name)
    if value is None or value == "-" or value == "":
        raise ValueError(f"packet observation is missing {name}")
    try:
        return _int_value(value)
    except ValueError as exc:
        raise ValueError(f"packet observation has invalid {name}") from exc


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    parsed = int(value)
    if str(value).strip() not in (str(parsed), f"+{parsed}") and not isinstance(value, int):
        # Reject truncated numeric strings such as "12.5" and "80/tcp".
        raise ValueError(f"not an integer: {value!r}")
    return parsed


def _text(value: Any) -> str | None:
    if value is None or value == "-" or value == "":
        return None
    return str(value)


def _flow_complete(value: Any) -> tuple[bool, str | None]:
    if value is True or value == 1:
        return True, None
    if value is False or value == 0:
        return False, None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"t", "true", "1"}:
            return True, None
        if normalized in {"f", "false", "0"}:
            return False, None
    return False, "packet observation has invalid flow_complete marker"
