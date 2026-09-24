from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_ZEEK_TO_MODEL_FEATURES = {
    "Destination Port": "id.resp_p",
    "Total Fwd Packets": "orig_pkts",
    "Total Backward Packets": "resp_pkts",
    "Protocol": "ip_proto",
}


def detector_features_from_zeek(record: Mapping[str, Any]) -> dict[str, Any]:
    """Add only exact conn.log aliases needed by the current stateless models.

    Zeek's packet-level `history` marker `^` means its originator/responder
    direction was flipped. CIC-style forward/backward fields therefore cannot
    be mapped safely for such a record. All original fields remain unchanged.
    """
    features = dict(record)
    event_type = str(record.get("event_type", "")).strip().lower()
    if event_type != "conn":
        return features

    direction_is_flipped = "^" in str(record.get("history") or "")
    for target, source in _ZEEK_TO_MODEL_FEATURES.items():
        if target in features:
            continue
        if direction_is_flipped and target != "Protocol":
            continue
        value = record.get(source)
        if value is None or value == "" or value == "-":
            continue
        if target in {
            "Destination Port",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Protocol",
        }:
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
        features[target] = value

    return features
