"""Aggregate decoded DNS packet metadata into the notebook's 29 fields."""
from __future__ import annotations

from collections import Counter
from statistics import mean, median, pstdev, pvariance
from typing import Mapping, Sequence


def _summary(values: Sequence[float], prefix: str) -> dict[str, float]:
    if not values:
        values = [0.0]
    counts = Counter(values)
    common = next(value for value in values if counts[value] == max(counts.values()))
    avg, med, sd = mean(values), median(values), pstdev(values)
    return {
        f"{prefix}Variance": pvariance(values), f"{prefix}StandardDeviation": sd,
        f"{prefix}Mean": avg, f"{prefix}Median": med, f"{prefix}Mode": common,
        f"{prefix}SkewFromMedian": avg-med, f"{prefix}SkewFromMode": avg-common,
        f"{prefix}CoefficientofVariation": sd/avg if avg else 0.0,
    }


def aggregate_dns_packets(packets: Sequence[Mapping[str, object]]) -> dict[str, float]:
    """Input is one ordered client/resolver exchange; times are Unix seconds.

    Each item requires timestamp, length and direction (sent/received); the
    matched DNS response latency in seconds is optional.
    """
    if not packets:
        raise ValueError("At least one DNS packet is required")
    ordered = sorted(packets, key=lambda item: float(item["timestamp"]))
    times = [float(item["timestamp"]) for item in ordered]
    lengths = [float(item["length"]) for item in ordered]
    sent = sum(float(item["length"]) for item in ordered if item.get("direction") == "sent")
    received = sum(float(item["length"]) for item in ordered if item.get("direction") == "received")
    duration = max(times[-1]-times[0], 0.0)
    result = {"Duration": duration, "FlowBytesSent": sent,
              "FlowSentRate": sent/duration if duration else 0.0,
              "FlowBytesReceived": received,
              "FlowReceivedRate": received/duration if duration else 0.0}
    result.update(_summary(lengths, "PacketLength"))
    result.update(_summary([b-a for a,b in zip(times,times[1:])] or [0.0], "PacketTime"))
    result.update(_summary([float(item["response_time"]) for item in ordered if item.get("response_time") is not None], "ResponseTimeTime"))
    return result
