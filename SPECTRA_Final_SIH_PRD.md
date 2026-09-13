# SPECTRA
## Final Product Requirements Document (PRD)
### AI-Based Passive Detection of Cyber Threats in Unidirectional IP Traffic

**Document status:** Final implementation PRD / SIH-ready working specification  
**Version:** 2.0  
**Prepared:** September 2026  
**Primary use:** Final engineering, validation, SIH demonstration, release control and judging readiness

---

# 1. Executive Summary

SPECTRA is a passive, AI-assisted network threat detection platform designed for critical-infrastructure and Operational Technology (OT) environments where the monitoring system must not interfere with the production network.

The central security constraint is architectural: traffic is copied from a monitored gateway/peering link into a monitoring enclave through a passive mirror, TAP, or hardware-enforced one-way path. The monitoring enclave is intentionally unable to send probes, complete handshakes with production endpoints, issue mitigation commands, or establish a return path into the protected network.

Inside the monitoring enclave, SPECTRA converts network observations into structured telemetry using Zeek, normalizes heterogeneous records, manages detector-specific temporal context, extracts features, invokes multiple machine-learning and behavioral detectors, produces standardized evidence-backed alerts, and exposes those alerts through REST and WebSocket interfaces to a real-time dashboard.

The product is not defined merely as a collection of ML models. Its value is the complete operational pipeline:

```text
ONE-WAY / PASSIVE TRAFFIC
        ↓
PASSIVE CAPTURE
        ↓
ZEEK TELEMETRY
        ↓
VALIDATION + INGESTION
        ↓
NORMALIZATION
        ↓
ORDERING / WINDOWING
        ↓
FEATURE EXTRACTION
        ↓
MULTI-DETECTOR INFERENCE
        ↓
CORRELATION + RISK
        ↓
STANDARDIZED ALERT
        ↓
REST / WEBSOCKET
        ↓
SOC DASHBOARD
```

The final product must also prove that it works under measurable operating conditions. A claim of “real time” is not accepted without capture-to-alert latency measurements, sustained throughput measurements, packet/capture-loss evidence, resource usage, queue behavior, and per-detector correctness results.

---

# 2. Product Decision: Are We Ready to Start the Final Project?

## 2.1 Decision

**Yes: the project can now enter final implementation. The PRD now freezes the major architectural decisions, interfaces, acceptance rules, evidence requirements, deployment topology, demonstration plan, and release gates. Future bugs discovered during implementation are handled by the test/failure process rather than by reopening the architecture unless a release-blocking defect requires it.**

There is no longer a major ambiguity about the intended architecture or the problem we are solving. However, there are still **implementation and validation gates** that must be completed before the product can honestly be called SIH-complete.

The correct approach is not to pause development waiting for perfection. Instead:

```text
FINAL IMPLEMENTATION
        ↓
P0 ACCEPTANCE GATES
        ↓
MEASUREMENT
        ↓
DETECTOR VALIDATION
        ↓
DEMO REHEARSAL
        ↓
SIH RELEASE CANDIDATE
```

## 2.2 What remains

The remaining work is execution of the frozen specification and its acceptance gates. The major remaining work falls into five groups:

1. **Prove real-time behavior:** capture-to-alert latency, p50/p95/p99, windowing delay and dashboard delivery.
2. **Prove throughput and loss behavior:** packets/sec, flows/sec, Mbps, Zeek capture loss, telemetry drops, queue pressure and resource usage.
3. **Prove detector correctness:** dedicated validation fixtures for all required threat families, including C2, DNS tunnelling, TLS/QUIC and exfiltration.
4. **Prove model reproducibility:** self-contained model artifacts, exact feature/preprocessing schemas, pinned compatible runtime and thresholds.
5. **Prove the passive security boundary:** demonstrate passive observation in the prototype and clearly distinguish this from a physical data diode.

The project materials already identify these issues as critical gaps rather than optional polish.

---

# 3. Problem Statement

Critical-infrastructure operators observe gateway and peering links using passive mirroring or hardware data diodes that copy traffic into a monitoring enclave in one direction only.

The monitoring enclave can observe the traffic crossing the boundary but has no physical or protocol-level path back into the production network. This is deliberate: a compromised monitoring system must not become a pivot into the protected network, and the evidence path should remain clean for forensic use.

Therefore, the intelligence layer must operate using only passively collected information such as:

- packet captures,
- flow records,
- Zeek-derived metadata,
- DNS metadata,
- TLS/QUIC metadata,
- timing,
- packet/byte statistics,
- protocol metadata.

The system must not:

- send probes,
- perform active scanning,
- complete a handshake with an observed endpoint,
- send mitigation commands,
- block traffic inline,
- modify production traffic,
- depend on decrypting TLS/QUIC payloads.

The objective is to detect, classify and score threats in near real time using only information available on the observation side.

---

# 4. Required Threat Coverage

The SIH problem statement defines six threat families. For implementation, SPECTRA may use seven detector modules because DGA and DNS tunnelling are implemented as separate detection paths.

Therefore, the documentation shall use:

> **Six threat families implemented through seven detector modules.**

## 4.1 Threat family matrix

| Threat family | Required coverage | Detection basis |
|---|---|---|
| Volumetric / protocol DDoS | SYN flood, UDP reflection/amplification, spoofed-source flood | Flow rate, packet/byte rate, SYN behavior, source diversity/entropy, protocol behavior |
| Botnet C2 beaconing | Fixed periodicity, jittered and low-and-slow behavior | Inter-arrival times, repetition, periodicity, temporal statistics |
| DGA + DNS tunnelling | Suspicious generated domains and covert DNS behavior | Entropy, n-grams, lexical features, query length, type/volume/timing statistics |
| Malware in encrypted sessions | TLS and QUIC metadata-only detection | Fingerprints/metadata, packet size/timing behavior, session context |
| Reconnaissance / port scan | Host and port fan-out | Destination diversity, port fan-out, connection behavior |
| Data exfiltration | Unusual outbound volume/asymmetry | Byte ratios, flow asymmetry, temporal/volume anomalies |

---

# 5. Product Goals

## P0 goals

- Passively monitor copied network traffic.
- Maintain strict read-only ingest semantics.
- Process events incrementally rather than waiting for an entire dataset.
- Produce bounded and measurable detection latency.
- Demonstrate a sustained throughput target.
- Prevent uncontrolled queue/memory growth.
- Detect all required threat families.
- Produce evidence-backed standardized alerts.
- Deliver alerts through REST and WebSocket interfaces.
- Support reproducible PCAP-based testing.
- Support safe live demonstration through a controlled test network.
- Keep production-side interaction out of scope.

## P1 goals

- Asset registry and asset criticality.
- Expected-flow baseline.
- Alert correlation.
- Incident objects and timelines.
- Risk scoring.
- Model provenance and model manifests.
- Evidence lineage/integrity.
- Drift monitoring.
- Better analyst workflows.

## P2 goals

- Physical data-diode integration.
- Distributed monitoring sensors.
- NetFlow/IPFIX/sFlow ingestion.
- High-availability deployment.
- Enterprise identity/RBAC.
- SIEM integration.
- Long-term analytics.

---

# 6. Non-Goals

SPECTRA is not:

- an inline IPS,
- an automated blocking system,
- an active scanner,
- a malware execution platform,
- a payload decryption platform,
- a replacement for a complete SOC,
- a complete incident-response platform,
- a NIST certification/compliance product,
- a Kubernetes-scale distributed platform for the MVP.

The project should not add infrastructure merely to create an impressive diagram. The original development guidance explicitly favored a small deployment and warned against unnecessary Kubernetes/microservice complexity.

---

# 7. Security and Threat Model

## 7.1 Attacker model

SPECTRA assumes attackers may:

- generate high-volume traffic,
- spoof source information,
- perform reconnaissance,
- establish command-and-control communication,
- use algorithmically generated domains,
- tunnel information over DNS,
- use encrypted protocols,
- manipulate packet timing,
- manipulate burst size,
- vary beacon timing,
- attempt data exfiltration.

## 7.2 SPECTRA capabilities

SPECTRA may:

- observe copied traffic,
- store derived telemetry,
- compute features,
- run models,
- score risk,
- correlate evidence,
- generate alerts,
- provide intelligence to an analyst.

## 7.3 SPECTRA limitations

SPECTRA must never assume it can:

- ask the source for more information,
- query the destination,
- send probes,
- complete its own handshake with the endpoint,
- block the endpoint,
- issue a remediation command,
- alter the observed production traffic.

---

# 8. Prototype Network Architecture

## 8.1 Recommended SIH demonstration

The recommended minimum live setup is:

```text
                 TEST / SIMULATED PRODUCTION SIDE

              Laptop B
          Controlled traffic
                 │
                 │
                 ▼
              Laptop C
        Simulated target/service
                 │
                 │
           ┌─────▼─────┐
           │  Managed   │
           │  Ethernet  │
           │  Switch    │
           │   SPAN     │
           └─────┬─────┘
                 │
          Mirror/SPAN port
                 │
                 ▼
        ┌───────────────────┐
        │     Laptop A      │
        │      SPECTRA      │
        │                   │
        │ Zeek → Backend    │
        │      → ML         │
        │      → Alert      │
        │      → Dashboard  │
        └───────────────────┘
```

Laptop A must receive a copy of traffic and must not be placed inline between B and C.

## 8.2 Optional distributed DDoS setup

For a visually convincing distributed-source scenario:

```text
Laptop B1 ─┐
Laptop B2 ─┼──► Laptop C
Laptop B3 ─┘
```

with Laptop A receiving the mirrored copy.

This requires:

- four source/target laptops plus SPECTRA if using three independent sources,
- one managed switch.

This is optional because distributed/spoofed scenarios can also be demonstrated safely and reproducibly using prepared PCAP fixtures.

## 8.3 Physical data diode vs SPAN

A SPAN port demonstrates **passive observation**, not a hardware-enforced one-way data diode.

The presentation must state:

> “For the prototype, we simulate the passive observation boundary with a switch mirror/SPAN port. Production deployment would place SPECTRA behind an appropriate passive TAP or hardware-enforced unidirectional gateway/data diode.”

Never describe a SPAN port as a data diode.

---

# 9. Source Modes

SPECTRA must support two evidence modes.

## 9.1 Replay mode

```text
PCAP
 ↓
Zeek
 ↓
Zeek logs
 ↓
SPECTRA
```

Purpose:

- reproducibility,
- detector validation,
- regression testing,
- benchmark repeatability.

## 9.2 Live/passive mode

```text
Observed traffic
 ↓
Passive TAP / SPAN / one-way boundary
 ↓
Live Zeek
 ↓
SPECTRA
```

Purpose:

- streaming demonstration,
- realistic telemetry timing,
- deployment validation.

The two modes must share the same downstream detection pipeline as much as practical.

---

# 10. Core System Architecture

```text
┌────────────────────────────────────────────────────────┐
│              Critical / Test Network                   │
└──────────────────────────┬─────────────────────────────┘
                           │
                     traffic copy
                           │
                           ▼
                 ┌───────────────────┐
                 │ Passive Boundary  │
                 │ TAP / SPAN /      │
                 │ Data Diode        │
                 └─────────┬─────────┘
                           │
                           ▼
                        ZEEK
                           │
           ┌───────────────┴────────────────┐
           │                                │
        Telemetry                       Health data
           │                                │
           ▼                                ▼
   Validation / Ingest              Capture-loss monitor
           │
           ▼
      Normalization
           │
           ▼
    Ordering / lateness
           │
           ▼
      Window manager
           │
           ▼
    Feature extraction
           │
     ┌─────┼────────────────────────────┐
     ▼     ▼       ▼       ▼      ▼     ▼
    DDoS   C2     DGA     DNS    TLS   Recon
                                    │
                                  Exfil
     └─────┴───────┴───────┴─────┴─────┘
                           │
                           ▼
                Prediction + uncertainty
                           │
                           ▼
                   Evidence extraction
                           │
                           ▼
                Correlation + Risk Engine
                           │
                           ▼
                    Alert / Incident
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
              REST API           WebSocket
                 │                   │
                 └─────────┬─────────┘
                           ▼
                     React Dashboard
```

---

# 11. Component Responsibilities

| Component | Responsibility |
|---|---|
| Passive boundary | Provide copied/one-way traffic observation |
| Zeek | Convert observed network traffic into structured metadata |
| Capture health | Monitor packet loss, lag and sensor health |
| Ingestion | Read supported Zeek telemetry |
| Validation | Reject/quarantine malformed records |
| Normalization | Map heterogeneous inputs to a common schema |
| Reordering | Handle timestamp disorder within a defined lateness bound |
| Windowing | Maintain detector-specific temporal context |
| Feature engine | Create exact features required by each detector |
| Detector adapters | Present a common interface to heterogeneous models |
| ML runtime | Load models and produce predictions |
| Evidence engine | Return human-readable reasons/features |
| Correlation | Link alerts into a possible incident |
| Risk engine | Combine confidence, asset criticality, persistence and context |
| Alert engine | Create the standardized alert object |
| Alert store | Retain recent alerts |
| FastAPI | REST + WebSocket backend |
| React | Analyst-facing dashboard |
| Metrics | Track throughput, latency, drops and health |
| Docker | Reproducible deployment |

---

# 12. Canonical Event Schema

Every supported telemetry record must be normalized into a common structure.

Minimum common fields:

```json
{
  "event_id": "EVT-...",
  "observed_at": "2026-09-13T10:00:00.123Z",
  "ingested_at": "2026-09-13T10:00:00.180Z",
  "src_ip": "192.0.2.10",
  "src_port": 1234,
  "dst_ip": "198.51.100.20",
  "dst_port": 443,
  "proto": "TCP",
  "log_type": "conn",
  "flow_id": "...",
  "raw": {}
}
```

Protocol-specific data belongs in `raw` or a typed extension.

The schema must not incorrectly require TCP/UDP/ICMP-only semantics for every event type.

DNS/TLS/QUIC records must be able to exist without fabricated fields.

---

# 13. Time Semantics

Every event must distinguish:

```text
observed_at
ingested_at
feature_ready_at
inference_started_at
inference_finished_at
alert_created_at
delivered_at
```

All externally visible timestamps should be UTC-aware.

This supports both performance measurement and forensic lineage.

---

# 14. Event Ordering and Late Events

Temporal detectors cannot assume events arrive in timestamp order.

The system must use a defined lateness policy:

```text
Incoming events
      ↓
Reorder buffer
      ↓
Timestamp-ordered events
      ↓
Window / detector
```

Configuration must define:

- maximum allowed lateness,
- buffer capacity,
- late-event behavior,
- drop/quarantine behavior,
- metrics.

Example policy:

```text
within lateness bound
    → reorder/process

outside lateness bound
    → mark late
    → process using defined policy or quarantine
    → increment late_event metric
```

---

# 15. Windowing Model

The logical context window and scoring frequency are separate.

Example:

```text
Context window = 60 seconds
Scoring interval = 1 second
```

Conceptually:

```text
last 60 seconds
────────────────────────────────────────
       ↑       ↑       ↑       ↑
      1s      1s      1s      1s
     score   score   score   score
```

This allows a detector to retain temporal context without automatically waiting the full 60 seconds before every prediction.

However, scoring cadence must remain compatible with the model's training feature semantics.

## 15.1 Detector-specific strategy

| Detector | Context | Scoring concept |
|---|---|---|
| DDoS | Multiple statistical horizons | Frequent rolling evaluation |
| Port Scan | Per-source history | Frequent evaluation |
| C2 | Chronological repeated flows | Incremental sequence evaluation |
| DGA | Query/domain level | Near-event evaluation |
| DNS Tunnel | Aggregated DNS statistics | Rolling/periodic evaluation |
| TLS/QUIC | Session metadata + baseline | Session/incremental evaluation |
| Exfiltration | Outbound volume context | Rolling statistical evaluation |

---

# 16. Feature Contract

Every detector must expose:

```text
detector_name
detector_version
required_features
preprocessing_version
model_version
threshold
predict(...)
evidence(...)
```

A model must never silently receive an approximate or placeholder feature vector.

The product must reject startup when required artifacts or schemas are missing.

---

# 17. Model Artifact Packaging

Each detector must become a self-contained deployable unit.

Recommended structure:

```text
models/
  ddos/
    model.*
    preprocessor.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  c2/
    model.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  dga/
    model.*
    vectorizer.*
    dictionary.*
    feature_schema.json
    config.yaml
    model_card.md

  ...
```

## Required manifest fields

```yaml
model_name:
model_version:
framework:
framework_version:
python_version:
feature_schema:
preprocessor_version:
threshold:
training_dataset:
training_date:
evaluation_report:
artifact_checksum:
```

---

# 18. Detector Requirements

## 18.1 DDoS

Required evidence should include, where applicable:

- packets/sec,
- bytes/sec,
- SYN ratio,
- source count,
- source-IP entropy,
- flow rates,
- protocol distribution,
- bidirectional/asymmetry statistics.

Validation must cover:

- SYN flood,
- UDP reflection/amplification-like behavior,
- spoofed-source flood,
- benign high-volume traffic.

A high packet rate alone must not be treated as sufficient proof of DDoS.

---

## 18.2 C2 Beaconing

Required temporal features should include, where model-compatible:

- mean inter-arrival time,
- median inter-arrival time,
- standard deviation,
- variance,
- coefficient of variation,
- min/max inter-arrival time,
- connection count,
- destination repetition,
- periodicity,
- autocorrelation,
- burstiness.

Validation fixtures:

```text
fixed periodic beacon
jittered beacon
low-and-slow beacon
multiple destinations
legitimate periodic service
```

C2 detection latency must explicitly include the time required to collect enough observations to establish the behavior.

---

## 18.3 DGA

Required feature classes:

- domain length,
- SLD length,
- entropy,
- digit ratio,
- vowel/consonant ratios,
- unique-character ratio,
- dictionary match,
- n-gram features.

All auxiliary artifacts, especially the fitted vectorizer and dictionary, must be packaged with the model.

Validation must include:

- normal domains,
- CDN/cloud domains,
- short/random-looking benign names,
- generated malicious domains,
- mixed DNS traffic.

---

## 18.4 DNS Tunnelling

The aggregation layer is mandatory.

```text
DNS events
   ↓
session/query grouping
   ↓
statistical aggregation
   ↓
29-feature vector
   ↓
model
```

Required evidence should combine:

- lexical characteristics,
- query length,
- entropy,
- query frequency,
- NXDOMAIN behavior,
- record-type distribution,
- request/response sizes,
- timing/inter-arrival information.

A hidden or undocumented upstream feature-builder dependency is not allowed.

---

## 18.5 TLS / QUIC Malware

The product must explicitly separate:

```text
TLS detection path
```

and:

```text
QUIC detection path
```

Required validation must verify the actual observable metadata path rather than relying on the detector name.

Candidate feature classes include:

- TLS version,
- cipher information,
- extensions,
- SNI where visible,
- ALPN,
- certificate metadata,
- JA3/JA3S/JA4 where available,
- packet size behavior,
- timing behavior,
- session behavior.

No payload decryption is allowed.

QUIC metadata must actually flow from the capture/log source into the detector path if the product claims QUIC coverage.

---

## 18.6 Port Scanning / Reconnaissance

Required evidence may include:

- unique destination ports,
- unique destination hosts,
- connection count,
- connection duration,
- unanswered/failed connection behavior,
- fan-out rate.

Model score and heuristic score must remain distinct.

Do not label a heuristic-derived score as a model probability.

---

## 18.7 Data Exfiltration

Exfiltration is a **required threat family**.

Required analysis should cover:

- outbound/inbound byte asymmetry,
- large outbound transfers,
- abnormal destination behavior,
- flow duration and rate,
- temporal persistence.

The current product must not classify exfiltration as “optional” in final documentation.

---

# 19. Prediction and Confidence

The following fields must be separated:

```text
raw_model_probability
calibrated_confidence
heuristic_score
combined_risk_score
```

A heuristic score must never be represented as a calibrated model probability.

Where calibration is implemented, the model card must state how it was evaluated.

---

# 20. Standard Alert Schema

The MVP schema is the P0 contract. The enhanced schema below includes P1 fields that are optional until the corresponding P1 subsystem is implemented.

Minimum SIH-required schema:

```json
{
  "alert_id": "...",
  "timestamp": "...",
  "flow_id": "...",
  "threat_class": "...",
  "confidence": 0.91,
  "severity": "HIGH",
  "evidence": {}
}
```

Recommended final schema:

```json
{
  "alert_id": "ALT-...",
  "incident_id": "INC-...",
  "observed_at": "...",
  "alert_created_at": "...",
  "delivered_at": "...",
  "flow_id": "...",
  "asset_id": "...",
  "src_ip": "...",
  "src_port": 0,
  "dst_ip": "...",
  "dst_port": 0,
  "protocol": "TCP",
  "threat_class": "DDoS",
  "severity": "CRITICAL",
  "raw_model_probability": 0.94,
  "calibrated_confidence": 0.91,
  "heuristic_score": null,
  "risk_score": 92,
  "model": "ddos_xgb",
  "model_version": "1.2",
  "feature_schema": "ddos-v4",
  "evidence": {},
  "evidence_hash": "...",
  "status": "NEW"
}
```

---

# 21. Severity Model

Severity must not be:

```text
confidence > 0.9 → critical
```

Instead use a documented mapping involving:

```text
confidence
+
threat family
+
evidence strength
+
persistence
+
traffic impact
+
asset criticality
```

Example:

```text
Model confidence
       +
Asset criticality
       +
Persistence
       +
Threat impact
       ↓
Severity
```

---

# 22. Asset Registry

## P1 requirement

The system should maintain a lightweight registry:

```text
asset_id
asset_name
ip
zone
asset_type
criticality
owner
expected_services
expected_communications
```

Example:

```text
PLC-07
IP: 10.10.20.7
Zone: Control Network
Criticality: CRITICAL
Expected peers:
  HMI-02
  Historian-01
```

This allows:

```text
DDoS
+
critical asset
=
higher operational priority
```

without altering the underlying ML model.

---

# 23. Expected-Flow / Behavioral Baseline

The system should learn or maintain expected communication patterns.

Example:

```text
PLC-07
normally communicates with:
  Historian-01
  HMI-02
```

Observed:

```text
PLC-07 → unknown external address
```

This is useful even if no ML detector fires.

The baseline should be explainable:

```text
expected peers
expected ports
expected protocol
expected rate
expected time-of-day behavior
```

---

# 24. Correlation Engine

Individual alerts must be correlatable.

Example:

```text
Port Scan
    ↓
C2 Beacon
    ↓
DGA
    ↓
TLS anomaly
    ↓
Exfiltration
```

becomes:

```text
Incident #1042
Possible Host Compromise
```

Correlation should use:

- source asset,
- destination asset,
- temporal proximity,
- shared flow/entity identifiers,
- threat relationship,
- severity,
- persistence.

Correlation must not invent evidence.

---

# 25. Incident Lifecycle

Recommended states:

```text
NEW
ACKNOWLEDGED
INVESTIGATING
CONFIRMED
FALSE_POSITIVE
RESOLVED
```

Each incident should contain:

- linked alerts,
- timeline,
- analyst notes,
- current status,
- affected assets,
- risk score.

This is P1, not a blocker for the first end-to-end detector demonstration.

---

# 26. Evidence Lineage and Forensic Integrity

Because the problem statement explicitly mentions forensic chain of custody, each alert should be traceable back to its source telemetry.

Recommended lineage:

```text
Observed traffic
      ↓
source log
      ↓
event_id
      ↓
feature snapshot
      ↓
model/version
      ↓
prediction
      ↓
alert
```

At minimum retain:

- source log name,
- source record identifier or deterministic reference,
- observed timestamp,
- ingestion timestamp,
- processing timestamp,
- model version,
- feature-schema version,
- evidence hash.

A lightweight hash/lineage scheme is sufficient for the prototype. A full immutable forensic store is not required for the MVP.

The persistent evidence store must support a documented backup/export and restore procedure for SIH demonstration and recovery testing.

---

# 27. REST API

Required endpoints:

```text
GET /health
GET /stats
GET /alerts
GET /alerts/{id}
```

Recommended P1 endpoints:

```text
GET /assets
GET /assets/{id}
GET /incidents
GET /incidents/{id}
GET /models
GET /metrics
```

FastAPI is the Python framework implementing these interfaces.

---

# 28. WebSocket

Required:

```text
/ws
```

Purpose:

- real-time alerts,
- live pipeline status where appropriate,
- dashboard updates.

The frontend must not need to poll `/alerts` every second to emulate real-time behavior.

The API contract must expose a schema/API version in documentation and responses so future alert-schema changes can be made without silently breaking the dashboard.

---

# 29. Latency Architecture

## 29.1 Latency definition

The main product metric is:

> **Capture-to-alert latency**

not only model inference time.

The full path is:

```text
Observed
  ↓
Zeek
  ↓
Ingest
  ↓
Queue
  ↓
Window
  ↓
Features
  ↓
Inference
  ↓
Alert
  ↓
WebSocket
  ↓
Dashboard
```

## 29.2 Required timestamps

```text
t0 = observed_at
t1 = Zeek/log availability
t2 = ingested_at
t3 = feature_ready_at
t4 = inference_started_at
t5 = inference_finished_at
t6 = alert_created_at
t7 = delivered_at
```

## 29.3 Required metrics

```text
capture_to_alert
capture_to_dashboard
zeek_to_ingest
queue_wait
window_wait
feature_time
inference_time
alert_generation_time
delivery_time
```

Report:

```text
P50
P95
P99
MAX
```

Do not use a single average as the only latency claim.

---

# 30. Throughput

The system must state and demonstrate a **measured** throughput.

At minimum record:

```text
packets/sec
flows/sec
Mbps
telemetry events/sec
```

Do not claim that 500 packets/sec was sustained by SPECTRA simply because the PCAP was generated at 500 pps.

The previous final replay processed 5,920 accepted telemetry events with approximately 60.6 telemetry events/sec replay processing throughput. This number is useful but is **not** a 500-pps network throughput claim.

---

# 31. Performance Benchmark

Run a controlled benchmark at increasing input rates, for example:

```text
500 pps
1,000 pps
5,000 pps
10,000 pps
```

Only retain rates actually achieved.

For each rate record:

| Metric | Required |
|---|---|
| Input packets/sec | Yes |
| Input flows/sec | Yes |
| Input Mbps | Yes |
| Zeek processing | Yes |
| SPECTRA events/sec | Yes |
| Capture loss | Yes |
| Telemetry drops | Yes |
| Queue peak | Yes |
| CPU | Yes |
| RAM | Yes |
| Detection latency P50 | Yes |
| Detection latency P95 | Yes |
| Detection latency P99 | Yes |
| Max latency | Yes |
| Detector failures | Yes |

---

# 32. Loss Budget

The system must distinguish:

```text
Network packets
      ↓
Capture loss
      ↓
Zeek records
      ↓
SPECTRA accepted events
      ↓
SPECTRA processed events
      ↓
Alerts
```

Metrics must distinguish:

- capture loss,
- unsupported records,
- malformed records,
- SPECTRA queue drops,
- detector failures.

The previous test demonstrated 5920 received and processed with zero SPECTRA drops after replay backpressure was fixed, but that does not itself prove zero packet loss at the capture layer.

---

# 33. Historical Replay Baseline (Reference Only)

The documented final replay currently establishes:

```text
Accepted normalized events: 5920
Processed:                  5920
SPECTRA dropped events:        0
Quarantined/unsupported:     431
Detector failures:             0
Queue depth at completion:     0
Alerts:                       969
```

Alert distribution recorded:

```text
DDoS:           517
DGA_DOMAIN:      22
MALWARE_TLS:    430
C2:               0
```

Replay timing recorded:

```text
Replay duration:       97.712473 sec
Telemetry throughput:  60.5859 events/sec
Avg inference:          0.012438 sec
Avg recorded E2E:       0.010206 sec
```

Interpretation:

- The replay backpressure path is functioning.
- The zero-drop figure is for accepted SPECTRA telemetry, not packet capture.
- The 60.6 events/sec figure is not the 500-pps network-rate claim.
- The recorded E2E metric is not automatically the full packet-observation-to-dashboard latency.

---

# 34. Current Known Gaps / Release Blockers

The project materials identify the following as conditions that must be resolved or re-verified before release.

## P0

### Real capture-to-alert latency
Current average inference/E2E measurements are insufficient.

### Sustained throughput
No defensible packet/flow/Mbps sustained target has been demonstrated yet.

### Capture loss
Zeek capture-loss evidence is required for the live sensor path.

### DDoS subtype validation
SYN, UDP reflection/amplification-like and spoofed-source scenarios must be tested separately.

### C2 validation
C2 must be tested using actual temporal beacon patterns, including jitter and low-and-slow behavior.

### DGA reproducibility
The fitted vectorizer/dictionary dependency must be packaged and verified.

### DNS tunnelling
The 29-feature aggregation path must be explicit, reproducible and tested.

### TLS/QUIC
The TLS and QUIC paths must be validated separately from actual observable metadata.

### Exfiltration
Must be treated as required, not optional.

### False-positive evaluation
Per-detector precision, recall, F1, FPR and FNR must be established on labeled evaluation data.

### Hard benign traffic
Legitimate periodic, encrypted, high-volume and DNS-heavy traffic must be part of evaluation.

### Model reproducibility
Artifact, preprocessing and runtime version compatibility must be pinned.

### Event ordering
Out-of-order event behavior and late-event policy must be implemented and tested.

### Model/feature contract
Every deployed model must have an exact feature schema and preprocessing contract.

### Alert evidence
Evidence must be structured and traceable.

### Passive-boundary demonstration
The final demo must show passive observation separately from API connectivity.

---

# 35. P1 Product Enhancements

These are valuable but should not block the first end-to-end release if time is limited:

- asset registry,
- asset criticality,
- expected communication baseline,
- alert correlation,
- incident lifecycle,
- risk scoring,
- evidence hashing,
- model manifest,
- drift monitoring,
- calibration,
- ATT&CK mapping.

---

# 36. Machine-Learning Evaluation

Every detector must have a model card containing:

```text
Model name
Model version
Training dataset
Dataset provenance
Feature list
Preprocessing
Class distribution
Train/validation/test split
Threshold selection
Precision
Recall
F1
Macro-F1 where relevant
FPR
FNR
Confusion matrix
Inference latency
Model size
Known limitations
```

Security evaluation must prioritize:

```text
Recall
False-positive rate
Latency
Generalization
```

rather than relying on accuracy alone.

---

# 37. Data Split Requirements

Avoid random leakage caused by splitting correlated samples from the same attack across train/test sets.

Prefer:

```text
Attack/session-aware split
or
time-aware split
or
dataset-aware cross-validation
```

Where possible, evaluate:

```text
Train A → Test A
Train A → Test B
Train B → Test A
```

This gives evidence about generalization.

---

# 38. Concept Drift

Network behavior changes over time.

The product should eventually detect:

```text
training distribution
        ↓
live distribution
        ↓
drift score
        ↓
model health status
```

A drift alert should not automatically retrain a model.

The first objective is:

> identify that the current traffic distribution may no longer match the model's training assumptions.

---

# 39. Failure Handling

The system must survive or explicitly account for:

```text
Zeek unavailable
Model unavailable
Model incompatible
Malformed event
Unsupported log
Queue full
Slow WebSocket client
Backend restart
Out-of-order event
Missing detector artifact
Missing feature
High traffic
Storage unavailable / database locked
Disk/retention limit reached
```

The expected behavior must be documented.

A detector failure should not kill the complete pipeline.

A malformed record should not crash the runtime.

A full queue should produce metrics rather than uncontrolled memory growth.

Persistent alert/evidence storage must survive a normal backend restart; a recovery test must verify that stored alerts, evidence hashes and model lineage remain readable after restart. Storage exhaustion or database-lock conditions must fail safely and visibly.

---

# 40. Observability

The dashboard/backend must expose:

```text
events_received
events_processed
events_dropped
malformed_events
late_events
detector_failures
queue_depth
queue_peak
capture_loss
input_rate
processing_rate
latency_p50
latency_p95
latency_p99
CPU
RAM
alerts_total
alerts_by_detector
```

Recommended telemetry names:

```text
spectra_events_received_total
spectra_events_processed_total
spectra_events_dropped_total
spectra_events_quarantined_total
spectra_detector_failures_total
spectra_queue_depth
spectra_input_rate
spectra_processing_rate
spectra_detection_latency_seconds
```

---

# 41. Dashboard Requirements

## 41.1 SOC overview

```text
SPECTRA

Threat level: HIGH

Input
Packets/sec      XXX
Flows/sec        XXX
Mbps             XXX

Pipeline
Received         XXX
Processed        XXX
Dropped            X
Quarantined        X
Queue              X

Latency
Capture→Alert P50 XXX
Capture→Alert P95 XXX
Capture→Alert P99 XXX
```

## 41.2 Threat panel

```text
DDoS
C2
DGA
DNS Tunnel
TLS/QUIC
Port Scan
Exfiltration
```

## 41.3 Alert panel

Every alert should show:

- threat,
- severity,
- confidence,
- source/destination,
- asset,
- evidence,
- timestamp,
- model version.

## 41.4 Incident panel

P1:

```text
Incident
 ↓
Related alerts
 ↓
Timeline
 ↓
Affected assets
 ↓
Risk
```

---

# 42. Testing Strategy

## Layer 1 — Unit tests

Test:

- parsing,
- normalization,
- feature calculations,
- thresholding,
- schemas,
- queue behavior,
- time handling.

## Layer 2 — Detector tests

For every detector:

```text
malicious input
benign input
missing feature
malformed input
wrong type
threshold boundary
```

## Layer 3 — Window tests

Test:

- grouping,
- expiration,
- rolling behavior,
- late events,
- out-of-order events,
- flush,
- state isolation.

## Layer 4 — Integration tests

```text
Zeek telemetry
→ NormalizedEvent
→ detector adapter
→ model
→ Prediction
→ Alert
```

## Layer 5 — API tests

```text
/health
/stats
/alerts
/alerts/{id}
WebSocket
```

## Layer 6 — End-to-end replay

```text
Zeek logs
→ ingestion
→ normalization
→ feature generation
→ inference
→ alert
→ store
→ REST
→ WebSocket
```

## Layer 7 — Performance tests

Run the complete pipeline under increasing traffic rates.

## Layer 8 — Failure tests

Intentionally fail components and verify isolation.

---

# 43. Required PCAP/Test Fixture Suite

The final repository should contain or reference clearly separated scenarios:

```text
pcap/
  benign/
    normal_dns.pcap
    normal_tls.pcap
    periodic_service.pcap
    high_volume_benign.pcap

  ddos/
    syn_flood.pcap
    udp_reflection.pcap
    spoofed_source.pcap

  c2/
    fixed_periodic.pcap
    jittered.pcap
    low_slow.pcap

  dns/
    dga.pcap
    dns_tunnelling.pcap

  tls/
    suspicious_tls.pcap

  quic/
    suspicious_quic.pcap

  recon/
    port_scan.pcap

  exfiltration/
    asymmetric_upload.pcap

  mixed/
    end_to_end_attack_chain.pcap

  stress/
    high_rate.pcap
```

The large mixed 500-pps capture should remain useful as a stress/replay fixture, but it must not be the only detector-validation dataset.

---

# 44. Synthetic Threat Generation Policy

For live demonstrations:

- use controlled synthetic traffic,
- use only authorized lab endpoints,
- do not deploy real malware,
- do not attack public systems,
- do not run malicious traffic through campus networks,
- use prepared PCAPs for scenarios requiring spoofing/reflection or distributed behavior that cannot be safely reproduced live.

For example, a C2 demonstration can be a benign test program producing periodic connections rather than real malware.

---

# 45. SIH Demonstration Plan

## Total target

7–10 minutes.

## Scene 1 — Problem

Show:

```text
Production
   ↓
Passive copy
   ↓
Monitoring enclave
```

Explain:

> “SPECTRA never needs to send traffic back to the monitored network.”

## Scene 2 — Network topology

Show:

```text
Source → Target
    \      /
     \    /
    mirrored copy
         ↓
      SPECTRA
```

## Scene 3 — Benign traffic

Show:

```text
normal HTTP/DNS/TLS
no critical alert
```

## Scene 4 — Port scan

Generate controlled fan-out:

```text
Target: multiple ports
```

Show the alert in real time.

## Scene 5 — DGA/DNS

Generate controlled suspicious-looking DNS queries.

Show:

```text
entropy
n-gram evidence
query information
confidence
```

## Scene 6 — C2

Show repeated periodic traffic:

```text
10s
10s
10s
jitter
...
```

Then show the C2 decision with temporal evidence.

## Scene 7 — TLS

Show encrypted traffic and state explicitly:

> “The payload is not decrypted; detection uses observable metadata/traffic behavior.”

## Scene 8 — DDoS

Use the prepared PCAP for:

- distributed behavior,
- reflection-like behavior,
- spoofed-source behavior.

Show:

```text
packet rate
source count
source entropy
SYN ratio
```

## Scene 9 — Exfiltration

Use synthetic high-asymmetry outbound transfer or prepared PCAP.

## Scene 10 — Performance

Show:

```text
Input rate
Processing rate
Capture loss
Drops
Queue
CPU
RAM
Latency P50/P95/P99
```

This is one of the most important screens.

---

# 46. Demonstration Fallback Plan

Never depend on live traffic alone.

## Primary

```text
Live passive traffic
→ Zeek
→ SPECTRA
→ Dashboard
```

## Secondary

```text
Prepared PCAP
→ Zeek
→ SPECTRA
→ Dashboard
```

## Emergency

```text
Pre-recorded screen/demo dataset
→ dashboard evidence
```

The fallback must use the same alert schema and UI as the live pipeline wherever possible.

---

# 47. What the Two-Laptop Test Proves

A two-laptop test:

```text
Laptop B → Laptop A:8000
```

proves:

- network connectivity,
- API reachability,
- service exposure.

It does **not** prove:

- passive packet capture,
- SPAN/TAP operation,
- data-diode behavior,
- Zeek visibility of another endpoint's traffic.

The final product documentation must keep these claims separate.

---

# 48. Deployment

## Development

```text
Python virtual environment
uvicorn
React development server
```

## Reproducible deployment

```text
Docker
+
Docker Compose
```

The deployment must pin compatible versions for:

- Python,
- XGBoost,
- scikit-learn,
- pandas,
- NumPy,
- SciPy,
- joblib,
- FastAPI,
- Uvicorn,
- Pydantic,
- Zeek for the live sensor path.

**Reference live-capture platform:** Linux is the preferred and supported SIH sensor platform. Zeek's Windows support is experimental and live packet capture on Windows requires an appropriate Npcap-linked build, so Windows remains a development/API environment unless the exact capture path is explicitly validated. Model artifacts must be validated during startup.

---

# 49. Container Security

The prototype should use:

- non-root containers where practical,
- read-only data mounts where practical,
- minimal capabilities,
- isolated networks,
- no unnecessary outbound dependencies,
- no production-side network path.

The monitoring environment should visibly preserve one-way/read-only semantics.

---

# 50. NIST Alignment

SPECTRA is **architecturally informed by** relevant NIST guidance. It does not claim compliance or certification.

## NIST SP 800-82 Rev. 3

Relevant because it addresses OT security while considering performance, reliability and safety requirements.

Mapping:

```text
OT environment
+
segmentation/isolation
+
non-disruptive monitoring
```

## NIST SP 800-94

Relevant to intrusion detection/prevention architecture and network-based monitoring.

Mapping:

```text
Network monitoring
+
passive sensor concepts
+
detection/alerting
```

## NIST CSF 2.0

SPECTRA primarily supports:

```text
IDENTIFY
DETECT
RESPOND support
```

The strongest direct mapping is **DETECT**: discovering and analyzing potentially adverse events.

## NIST SP 800-61 Rev. 3

SPECTRA alerts can become inputs to an organization's incident-response process.

The project must not claim to implement the entire incident-response lifecycle.

## NIST SP 1800-7

Relevant as a reference architecture for electric-utility situational awareness, particularly passive taps, collection, normalization, integrity/aggregation and visualization.

---

# 51. Additional Security Concepts

## MITRE ATT&CK

Recommended P1:

```text
Alert
 ↓
ATT&CK tactic
 ↓
ATT&CK technique
```

Only map techniques where the evidence supports the mapping.

Do not add ATT&CK IDs merely for presentation.

---

# 52. Current Project Baseline

The project materials establish a strong foundation:

```text
✓ Zeek integration
✓ Telemetry ingestion
✓ Normalization
✓ Streaming runtime
✓ Detector routing concept
✓ Standard alert concept
✓ REST API
✓ WebSocket
✓ React dashboard
✓ Bounded alert/event structures
✓ Detector failure accounting
✓ Malformed/unsupported telemetry quarantine
✓ Replay backpressure
✓ Docker/deployment path
✓ End-to-end replay
```

The final replay evidence also shows:

```text
5920 accepted normalized events
5920 processed
0 SPECTRA drops
0 detector failures
969 alerts
```

These are useful achievements.

---

# 53. What Must Not Be Claimed Yet

Until the P0 gates are completed, do not claim:

- “500 pps sustained end-to-end”;
- “sub-10 ms detection”;
- “zero packet loss”;
- “full QUIC detection”;
- “all six threat classes proven live”;
- “data-diode deployment” when only SPAN is used;
- “NIST compliant”;
- “94% confidence means a 94% probability of attack” unless calibrated;
- “all detectors are validated” solely because the models load;
- “real-time” solely because inference is fast.

---

# 54. Release Gates

The SIH release candidate is accepted only when:

## Gate 1 — Functional

```text
All required threat families have working execution paths.
```

## Gate 2 — Model

```text
All required model/preprocessing artifacts load reproducibly.
```

## Gate 3 — Streaming

```text
Events are processed incrementally.
```

## Gate 4 — Latency

```text
Capture→alert latency is measured and reported.
```

## Gate 5 — Throughput

```text
A sustained tested traffic target is documented.
```

## Gate 6 — Loss

```text
Capture loss and application-level drops are independently measured.
```

## Gate 7 — Quality

```text
Per-detector evaluation includes false-positive analysis.
```

## Gate 8 — Passive boundary

```text
The demo visibly demonstrates passive observation.
```

## Gate 9 — Evidence

```text
Every alert contains supporting evidence and lineage.
```

## Gate 10 — Demo

```text
Live demonstration + PCAP fallback both work.
```

---

# 55. Final Acceptance Test Matrix

| Area | Test | Pass condition |
|---|---|---|
| Passive architecture | Mirror/TAP visibility | SPECTRA sees copied traffic without being inline |
| Read-only constraint | Network inspection | No active probes/mitigation from SPECTRA |
| Zeek | Live/replay logs | Expected telemetry generated |
| Ingest | Normal log | Correct normalized event |
| Ingest | Malformed log | Quarantined, runtime remains healthy |
| Ordering | Out-of-order timestamps | Defined lateness policy works |
| DDoS | SYN | Detection/evidence generated |
| DDoS | UDP reflection-like | Detection/evidence generated |
| DDoS | spoofed-source simulation | Detection/evidence generated |
| C2 | periodic | Detection/evidence generated |
| C2 | jittered | Behavior evaluated correctly |
| DGA | generated domains | Detection/evidence generated |
| DNS tunnel | statistical session | Detection/evidence generated |
| TLS | metadata-only | Detection without payload decryption |
| QUIC | metadata-only | Separate verified path |
| Recon | fan-out | Detection/evidence generated |
| Exfiltration | asymmetric outbound transfer | Detection/evidence generated |
| Benign | normal traffic | Low false-positive behavior |
| REST | health/stats/alerts | Correct response |
| WebSocket | new alert | Delivered without polling |
| Latency | live event | Capture→alert P50/P95/P99 measured |
| Throughput | stress | Sustainable tested target documented |
| Capture loss | Zeek | Loss measured independently |
| Queue | overload | Bounded behavior and metrics |
| Detector failure | broken model | Other system components survive |
| Restart | backend restart | Defined recovery behavior |
| Reproducibility | clean environment | Models and dependencies load consistently |
| Dashboard | live alert | UI updates in real time |

---

# 56. Implementation Roadmap

## Phase 0 — Final baseline audit

Before making architectural changes:

```text
1. Verify current repository state.
2. Run detector smoke tests.
3. Run backend tests.
4. Run final replay.
5. Record current latency/throughput.
6. Record model artifact status.
7. Record current gaps.
```

This prevents fixing problems that have already been fixed.

---

## Phase 1 — P0 correctness

```text
1. Model/feature contracts
2. Missing DGA artifacts
3. DNS aggregation
4. C2 contract/validation
5. TLS/QUIC validation
6. Exfiltration execution path
7. DDoS subtype fixtures
8. Hard benign fixtures
```

---

## Phase 2 — P0 performance

```text
1. Stage timestamps
2. Capture→alert metric
3. P50/P95/P99
4. Window scoring cadence
5. Reordering buffer
6. Capture-loss measurement
7. packets/sec
8. flows/sec
9. Mbps
10. CPU/RAM
11. overload tests
```

---

## Phase 3 — P1 intelligence

```text
1. Asset registry
2. Asset criticality
3. Expected-flow baseline
4. Risk scoring
5. Alert correlation
6. Incident lifecycle
7. Timeline
```

---

## Phase 4 — P1 defensibility

```text
1. Model manifest
2. Evidence hashing
3. Cross-dataset evaluation
4. Calibration
5. Drift detection
6. ATT&CK mapping
```

---

## Phase 5 — SIH rehearsal

Run the entire system exactly as it will be shown to judges.

No development shortcuts.

No hidden manual edits.

No undocumented model swapping.

No localhost-only assumptions.

---

# 57. Risk Register

| Risk | Severity | Mitigation |
|---|---|---|
| False “real-time” claim | High | Capture→alert latency measurement |
| Throughput overclaim | High | packets/s + flows/s + Mbps benchmark |
| Packet loss hidden by zero app drops | High | Zeek capture-loss measurement |
| C2 detector mismatch | High | Dedicated temporal fixtures + exact feature contract |
| DGA vectorizer missing | High | Package vectorizer/dictionary |
| QUIC overclaim | High | Separate QUIC validation |
| Exfiltration incomplete | High | Make it a P0 detector path |
| Model version incompatibility | High | Pin runtime + artifact manifest |
| Out-of-order data | High | Reordering/lateness policy |
| Alert confidence ambiguity | Medium | Separate probability/heuristic/risk |
| Excessive dashboard complexity | Medium | Keep SOC views focused |
| Demo network isolation failure | High | Dedicated lab switch + controlled endpoints |
| Live demo failure | High | PCAP fallback |
| Over-engineering | Medium | Avoid unnecessary microservices/Kubernetes |
| Real malware misuse | High | Synthetic traffic and prepared PCAPs |

---

# 58. Product Differentiation

SPECTRA should not be presented as:

> “Another AI IDS.”

The differentiated product story is:

### 1. Passive by architecture

Detection happens from a copied/one-way observation path.

### 2. Multi-detector integration

Different threat models operate behind one common runtime.

### 3. Streaming

The system is designed for incremental processing rather than only end-of-run classification.

### 4. Evidence-backed alerts

An alert explains which observable features contributed to the decision.

### 5. Operational measurement

The platform reports:

```text
throughput
capture loss
queue pressure
latency
resource usage
```

### 6. Critical-infrastructure context

The architecture is designed around OT safety, isolation and non-disruptive monitoring.

### 7. Reproducibility

The same pipeline can operate on prepared PCAPs for repeatable validation.

---

# 59. Final Product Narrative

The product pitch should be:

> **SPECTRA is a passive AI-assisted network threat intelligence platform for critical infrastructure. It receives only a one-way copy of network activity, so the monitoring system never needs to probe or communicate back with production endpoints. Zeek converts that traffic into structured telemetry, SPECTRA normalizes and orders the events, builds detector-specific temporal and protocol features, and runs multiple ML and behavioral detectors covering DDoS, C2, DGA/DNS tunnelling, encrypted TLS/QUIC traffic, reconnaissance and exfiltration. Predictions are converted into standardized evidence-backed alerts, correlated into incidents where possible, and delivered through FastAPI and WebSockets to a real-time analyst dashboard. Crucially, SPECTRA measures capture loss, throughput, queue behavior and capture-to-alert latency so its near-real-time claim can be demonstrated rather than assumed.**

---

# 60. Final Definition of Done

SPECTRA is SIH-ready when the following statement is true:

```text
A controlled one-way/passive traffic source
        ↓
is observed without active interaction
        ↓
Zeek produces telemetry
        ↓
SPECTRA processes it incrementally
        ↓
required threat detectors execute correctly
        ↓
features and models are reproducible
        ↓
alerts contain evidence
        ↓
latency is measured from observation to alert
        ↓
throughput is measured in packets/s, flows/s and/or Mbps
        ↓
capture and application drops are distinguished
        ↓
results reach the dashboard in real time
        ↓
the same flow works from PCAP replay
        ↓
and the entire system can be demonstrated safely.
```

---

# 61. Final Engineering Principle

The project should now stop asking:

> “What else can we add?”

and start asking:

> **“Can we prove every claim we make?”**

The final engineering priorities are:

```text
CORRECTNESS
    ↓
MEASUREMENT
    ↓
REPRODUCIBILITY
    ↓
PASSIVE-BOUNDARY PROOF
    ↓
DEMONSTRATION
```

That is the standard this PRD is intended to enforce.

---

# 62. Reference Basis

## Project-source basis

This PRD consolidates the supplied SPECTRA project specification, implementation handoff material, detector audits, replay evaluation, latency analysis and demonstration planning documents.

The supplied material establishes the original mandatory flow:

```text
one-way traffic
→ passive ingestion
→ feature extraction
→ threat detectors
→ streaming inference
→ standardized alert
→ confidence/severity/evidence
→ dashboard
→ deployment
```

It also records the final replay results, model/feature integration issues and identified performance gaps.

## External reference basis

- NIST SP 800-82 Rev. 3, Guide to Operational Technology (OT) Security.
- NIST SP 800-94, Guide to Intrusion Detection and Prevention Systems.
- NIST Cybersecurity Framework 2.0.
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management.
- NIST SP 1800-7, Situational Awareness for Electric Utilities.
- Zeek documentation for network monitoring, common logs, capture-loss reporting, QUIC/common logs and live interface monitoring.

### Official URLs

- NIST SP 800-82 Rev. 3: https://csrc.nist.gov/pubs/sp/800/82/r3/final
- NIST SP 800-94: https://csrc.nist.gov/pubs/sp/800/94/final
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 1800-7: https://www.nccoe.nist.gov/energy/situational-awareness
- Zeek documentation: https://docs.zeek.org/

---

# 63. Current Release Classification

**PRD status:** Frozen for implementation  
**Architecture:** Defined and internally reconciled  
**Implementation:** Final integration and validation phase  
**Performance proof:** Pending execution of the defined benchmark  
**Threat validation:** Pending execution of the defined detector fixtures  
**Live passive demonstration:** Pending live sensor acceptance test  
**PCAP replay:** Working baseline with replay backpressure fix  
**SIH release status:** **Not yet released; release only after all P0 acceptance gates pass**  

The classification above is intentionally conservative. It does not mean the architecture is undecided; it means the implementation must now produce the evidence required by the frozen specification. No major architectural decision is intentionally left implicit; values that can only be known by measurement are defined as benchmark outputs and are not to be fabricated.


---

# 64. Final Engineering Contract — No Unresolved Design Decisions

This section freezes the implementation decisions that were previously described only as recommendations. The purpose is to prevent the team from beginning implementation with hidden assumptions.

## 64.1 Frozen architecture decisions

| Decision | Frozen implementation choice | Reason |
|---|---|---|
| Network observation | Passive copy through TAP/SPAN for prototype; hardware data diode/unidirectional gateway in production | Matches the one-way monitoring requirement without pretending SPAN is a data diode |
| Live sensor OS | Linux reference platform | Reliable live packet capture path for Zeek; Windows Zeek support is experimental |
| Traffic analyzer | Zeek | Produces structured network/security telemetry and capture diagnostics |
| Backend language | Python | Direct ML/model integration |
| API framework | FastAPI | REST + WebSocket in the same Python service |
| Live alert transport | WebSocket | Immediate server-to-client delivery |
| Query/state API | REST | Request/response access to health, stats, alerts and configuration-derived state |
| Frontend | React | Real-time dashboard state and visualization |
| Live queue | Bounded, non-blocking producer path with explicit drop accounting | Prevents unbounded memory growth |
| Replay queue | Backpressure-enabled replay path | Preserves correctness during offline validation |
| Temporal processing | Detector-specific context windows with periodic scoring; no universal window size | Preserves model semantics while avoiding unnecessary full-window waits |
| Event ordering | Reordering buffer with explicit maximum lateness | Required for temporal correctness |
| Evidence storage | Persistent SQLite metadata/evidence index plus append-only evidence records | Prevents loss of forensic lineage on process restart without introducing a large database stack |
| Model packaging | Self-contained artifact directory + manifest + checksum + feature schema | Prevents hidden preprocessing/model dependencies |
| Evaluation | Scenario + ground-truth manifest + machine-readable report | Makes metrics reproducible and auditable |
| Deployment | Docker/Compose for reproducibility; Linux sensor host for live capture | Keeps MVP deployment small and reproducible |
| Large distributed infrastructure | Out of scope for MVP | No Kafka/Kubernetes/Redis cluster unless a measured requirement appears |

## 64.2 Frozen operating modes

SPECTRA has exactly three runtime modes:

### LIVE

```text
MODE=LIVE
```

Requirements:

- no mock detector;
- no synthetic alerts;
- no automatic replay;
- passive/live Zeek input only;
- real timestamps and performance metrics;
- sensor interface must not have a route into the protected/test-production network.

### REPLAY

```text
MODE=REPLAY
```

Requirements:

- input is a named fixture or Zeek log set;
- ground-truth scenario is known;
- replay timing mode is explicit;
- replay backpressure is enabled;
- reports identify fixture, commit SHA, model versions and configuration.

### TEST

```text
MODE=TEST
```

Requirements:

- mocks may be enabled;
- test-only artifacts are allowed;
- this mode must never be the default production/demo mode.

---

# 65. Replay Timing Contract

Replay is not a single behavior. It must support three explicit modes.

| Mode | Definition | Purpose |
|---|---|---|
| FAST | Submit records as quickly as the lossless replay path can safely process them | Functional correctness and regression |
| FIXED_RATE | Pace the source to a configured packet/event rate | Throughput testing |
| TIMESTAMP_PRESERVING | Reproduce source-event relative timing from the recorded timestamps | Detection-latency testing and temporal-detector validation |

A benchmark result must always record which replay mode was used.

The existing final replay is classified as a **historical functional baseline**, not as proof of a 500-pps end-to-end network throughput claim. The baseline was 5,920 accepted normalized events, 5,920 processed, zero SPECTRA drops, zero detector failures and 969 alerts; it achieved approximately 60.6 telemetry events/sec in the replay evaluator. That number is telemetry processing throughput, not source packet rate.

---

# 66. Ground Truth and Evaluation Contract

## 66.1 Scenario manifest

Every detector-validation scenario must have a machine-readable manifest with at least:

```yaml
scenario_id:
threat_family:
subtype:
input_fixture:
expected_detection:
start_time:
end_time:
src_entities:
dst_entities:
expected_detector:
notes:
```

For benign scenarios:

```yaml
expected_detection: false
```

## 66.2 Evaluation outputs

Every detector evaluation must produce:

- TP;
- FP;
- TN;
- FN;
- precision;
- recall;
- F1;
- FPR;
- FNR;
- confusion matrix;
- first-detection timestamp;
- detection latency;
- missed-detection count;
- alert count;
- model version;
- feature schema version;
- dataset/fixture ID.

## 66.3 Leakage policy

Training, validation and test data must not split highly correlated records from the same attack/session across partitions. Prefer attack-aware, session-aware or time-aware separation. Cross-dataset testing must be used where data availability permits.

---

# 67. Exact P0 Performance Targets and Pass Criteria

The following are **engineering acceptance targets proposed for the final implementation**, not claims about current performance. They become release criteria only after the benchmark is executed and recorded on the reference system.

## 67.1 Minimum benchmark workload

The final performance test must include at least:

```text
500 packets/sec source traffic
```

for a sustained controlled run of at least 10 minutes, with a 60-second smoke test permitted before the full run, while recording:

- packets/sec;
- flows/sec;
- Mbps;
- telemetry events/sec;
- CPU;
- RAM;
- queue depth;
- capture loss;
- application drops;
- detector failures.

The team should continue increasing the rate until the system no longer satisfies its acceptance conditions. The highest passing rate becomes the published sustained throughput result.

## 67.2 Latency targets

Use two latency concepts:

### Processing SLA

Once a detector has enough evidence to score, **post-evidence processing overhead** should be:

```text
P95 ≤ 1 second
P99 ≤ 2 seconds
```

### Evidence-acquisition latency

For temporal detectors, the time required to collect enough observations is measured separately. It is not falsely reported as ML inference latency.

Report for every detector:

```text
first observable event → scoreable evidence
scoreable evidence → alert
first observable event → alert
```

The final report must include P50/P95/P99/MAX for each applicable latency.

## 67.3 Loss targets

For the controlled lab benchmark:

```text
SPECTRA application-event drops = 0
Detector failures = 0
Capture loss = 0% preferred
```

If non-zero capture loss is observed, the run fails the zero-loss release criterion and the result must be reported rather than hidden. A separate engineering stress result may still be documented with the exact loss rate.

## 67.4 Queue target

At the minimum benchmark rate:

```text
queue must remain bounded
queue peak must be recorded
queue must return to normal after the load ends
```

A full queue must cause the documented overflow/degradation behavior, never uncontrolled memory growth.

## 67.5 Benchmark procedure

1. Freeze repository commit and model manifest.
2. Record reference hardware/software profile.
3. Run a 60-second smoke test at the configured rate.
4. Run the full benchmark for at least 10 minutes.
5. Repeat each important rate at least three times.
6. Report median, P95 and P99 across runs where applicable.
7. Identify the highest rate that satisfies all release criteria.
8. Preserve the raw benchmark report alongside the summarized result.

---

# 68. Live Capture Reference Architecture

## 68.1 Reference topology

```text
             TEST / SIMULATED PRODUCTION

 Source B ───────────────► Target C
     │                         │
     │                         │
     └──────────────┬──────────┘
                    │
              Managed Switch
                    │
                 SPAN/TAP
                    │
                    ▼
          ┌─────────────────────┐
          │ Linux Sensor Host A │
          │                     │
          │ Sensor NIC ──► Zeek│
          │                     │
          │ Mgmt NIC ──► API   │
          └─────────────────────┘
```

## 68.1.1 Live-capture software contract

The reference live sensor must run a validated Zeek build on Linux. The exact capture interface name, driver, MTU, offload settings relevant to packet capture, capture mode and Zeek configuration must be recorded in the benchmark report. The live source must produce the exact log types required by the enabled detectors, including `conn.log`, `dns.log`, `ssl.log` and `quic.log` where the corresponding detector is enabled; additional diagnostic logs such as `capture_loss.log` and `reporter.log` must be collected for sensor-health evaluation.

Windows remains a development/API option only unless the exact Zeek+Npcap live-capture path has been explicitly validated for the final demonstration.

## 68.2 Interface separation

The live sensor host should use two logical planes:

### Sensor plane

- receives mirrored traffic;
- no default route toward the protected/test-production network;
- no application listener exposed on the sensor interface;
- packet capture only.

### Management plane

- backend/frontend access;
- administration;
- isolated lab management subnet.

## 68.3 Acceptance test

During the live demo:

1. Generate traffic from B to C.
2. Prove SPECTRA sees the mirrored copy.
3. Show source/target flow in Zeek.
4. Show the corresponding SPECTRA event.
5. Demonstrate that the sensor interface does not provide an outbound path toward B/C.
6. Keep API/dashboard access on the management plane.

A SPAN port remains a passive-observation demonstration, **not a hardware data diode**.

---

# 69. Capture Health and Loss Accounting

The sensor health layer must distinguish:

```text
source packets
   ↓
capture packets / capture-loss evidence
   ↓
Zeek records
   ↓
accepted SPECTRA events
   ↓
processed events
   ↓
alerts
```

Zeek diagnostics such as `capture_loss.log` and `reporter.log` must be collected in live/relevant test runs. The final report must explain exactly which layer each loss metric refers to.

The project must never state “zero packet loss” merely because `dropped_events=0` in SPECTRA.

---

# 70. Persistent Evidence and Forensic Lineage

## 70.1 Persistent records

The P0 evidence record must persist after process restart.

Store at least:

```text
alert_id
observed_at
alert_created_at
source_log
source_record_reference
event_id / flow_id
threat_class
model
model_version
feature_schema
model_score
severity
evidence_json
evidence_hash
configuration_version
```

## 70.2 Hashing

The evidence hash must be calculated from a canonical serialized representation. The canonical representation, hash algorithm and version must be documented.

## 70.3 Evidence lineage

```text
traffic observation
      ↓
source log
      ↓
normalized event
      ↓
feature snapshot
      ↓
model/version
      ↓
prediction
      ↓
alert
```

Any missing lineage link must be surfaced explicitly rather than silently fabricated.

---

# 71. Alert Deduplication and Alert-Storm Control

High-volume attacks can create thousands of similar observations. The system must separate **evidence count** from **analyst-facing alert count**.

## 71.1 Deduplication key

Minimum suggested key:

```text
threat_class + source_entity + destination_entity + detector + time_bucket
```

The exact key is detector-specific where required.

## 71.2 Required controls

- suppression/cooldown window;
- aggregated evidence count;
- first_seen;
- last_seen;
- representative flow IDs;
- count of supporting observations;
- maximum alert generation rate.

The raw telemetry must remain measurable even when alerts are aggregated.

---

# 72. Protocol and Addressing Scope

The final documentation must explicitly state the supported network scope.

At minimum document:

```text
IPv4: supported
IPv6: explicitly supported or explicitly out of scope
TCP: supported
UDP: supported
ICMP: observed/limited support as documented
VLAN-tagged traffic: supported or out of scope
GRE/VXLAN/encapsulated traffic: explicitly scoped
```

No feature may fabricate protocol-specific fields that do not exist in the source telemetry.

DNS, TLS, QUIC and future protocol-specific events must be represented through typed extensions rather than fake TCP-only fields.

---

# 73. Clock and Timestamp Contract

## 73.1 Wall-clock timestamps

Use UTC-aware timestamps for externally visible evidence.

## 73.2 Duration measurements

Use a monotonic clock for local processing-duration measurements so system clock adjustments do not corrupt latency calculations.

## 73.3 Multi-host synchronization

For multi-laptop demonstrations:

- synchronize clocks using a documented time source;
- record host identity;
- record clock synchronization status;
- report observed clock skew where measurable.

The latency calculation must distinguish wall-clock evidence time from local monotonic duration measurement.

---

# 74. Model Artifact Security and Reproducibility

Every model deployment must pass startup validation:

```text
artifact exists
↓
checksum matches
↓
framework/version compatible
↓
feature schema exists
↓
preprocessor exists
↓
auxiliary artifacts exist
↓
threshold/config valid
↓
model can execute a smoke inference
```

Startup must fail closed for a missing critical artifact. The service must not silently substitute a mock detector or an approximate feature vector in LIVE mode.

Python serialized artifacts such as pickle/joblib must come only from the trusted project artifact set; arbitrary untrusted model files must never be loaded.

---

# 75. API and Management Security

## 75.1 Demo environment

The SIH prototype may run on an isolated lab network without full enterprise authentication, provided that:

- it is not exposed to the public Internet;
- CORS is restricted to the dashboard origin(s);
- debug/reload mode is disabled in the final demonstration;
- only required ports are exposed;
- the management interface is isolated from the sensor interface.

## 75.2 Production direction

A production deployment should additionally provide:

- authenticated management access;
- role-based authorization;
- encrypted management transport;
- audit logging;
- secrets management.

These are not required to turn the current prototype into a full enterprise SOC platform, but the architecture must not prevent them.

---

# 76. Data Retention and Privacy

Define retention before release:

| Data | Prototype policy |
|---|---|
| Raw PCAP | Test-only/local unless deployment policy explicitly allows retention |
| Zeek telemetry | Configurable, documented retention |
| Alert/evidence records | Persistent for the configured incident/evaluation period |
| Model artifacts | Versioned and retained with checksums |
| Benchmark reports | Retained with experiment metadata |

IP addresses, DNS names and network metadata may be operationally sensitive. The project must document who can access stored evidence and avoid committing sensitive real-world captures to a public repository. Retention must be enforced by a deterministic rotation/expiry policy so storage cannot grow without bound.

---

# 77. Detector Acceptance Matrix

Each detector is considered **P0 complete** only when all of the following are satisfied:

| Detector | Positive fixtures | Negative fixtures | Evidence | Latency | Model contract | Pass condition |
|---|---|---|---|---|---|---|
| DDoS | SYN, UDP reflection-like, spoofed-source | benign high-volume | rate, source diversity/entropy, protocol indicators | measured | exact | all mandatory fixtures evaluated with documented outcomes |
| C2 | fixed periodic, jittered, low-and-slow | legitimate periodic service | IAT/periodicity features | measured incl. acquisition | exact | temporal behavior evaluated and no hidden feature mismatch |
| DGA | generated domains | benign/CDN/cloud/random-looking | lexical, entropy, n-gram | measured | exact | vectorizer/dictionary packaged |
| DNS Tunnel | statistical tunnel | normal DNS | volume, lexical, timing, record type | measured | exact | aggregation path explicit and reproducible |
| TLS | suspicious encrypted session | legitimate TLS | metadata/fingerprint/size/timing where available | measured | exact | no payload decryption |
| QUIC | suspicious QUIC fixture | benign QUIC where available | actual QUIC observable metadata | measured | exact | separate verified path |
| Recon | port/host fan-out | normal client behavior | fan-out, failed/unanswered connections | measured | exact | model/heuristic scores separated |
| Exfiltration | asymmetric outbound transfer | normal upload/download | byte asymmetry, rate, destination, persistence | measured | exact | required path executes and reports evidence |

The table above is a release contract. “Model loads” alone never satisfies detector completion. For each positive/negative fixture, the experiment report must state the ground-truth label, observed result, first detection time when applicable, and PASS/FAIL according to the documented scenario criterion.

---

# 78. Confidence, Risk and Severity Contract

The system must expose distinct concepts:

```text
raw_model_probability / model_score
calibrated_confidence (only when calibration exists)
heuristic_score
risk_score
severity
```

### MVP

If calibration is not implemented, the UI must label the value as **Model Score** or **Model Probability (uncalibrated)** rather than implying statistical calibration.

### Asset-criticality fallback

If an asset registry is not available in the MVP, severity/risk calculation must fall back to network evidence, threat type, persistence and measured impact. The absence of asset context must never be represented as “low criticality.”

### Risk

Risk may incorporate:

```text
threat score
+ threat type
+ persistence
+ evidence strength
+ asset criticality (P1)
+ behavioral context (P1)
```

A heuristic score must never be presented as model probability.

---

# 79. Configuration Contract

All tunable runtime parameters must live in a validated central configuration layer.

Examples:

```text
queue size
replay mode
replay rate
maximum lateness
window sizes
scoring interval
thresholds
alert retention
log directories
model directories
sensor interface
management interface
```

Configuration must be reported at startup in a sanitized form so an evaluation result can be reproduced.

No critical production behavior may depend on an undocumented environment variable.

---

# 80. Scenario Runner and Reproducible Experiment Contract

A single command should be able to execute a named experiment:

```text
scenario runner
    ↓
load fixture
    ↓
load ground truth
    ↓
verify models/checksums
    ↓
start pipeline
    ↓
replay/capture
    ↓
collect metrics
    ↓
compare with ground truth
    ↓
write machine-readable report
    ↓
write human-readable summary
```

Every report must record:

- git commit SHA;
- machine profile;
- operating system;
- Python/Zeek versions;
- model versions/checksums;
- configuration hash;
- fixture ID;
- replay mode;
- input traffic statistics;
- output statistics;
- latency distributions;
- detection results;
- failures/warnings.

---

# 81. CI / Release Automation

The repository should run automatically on every integration branch:

```text
lint/syntax
 ↓
unit tests
 ↓
contract tests
 ↓
detector smoke tests
 ↓
artifact validation
 ↓
replay regression
 ↓
Docker build
```

The full high-rate performance benchmark need not run on every commit; it is an explicit release/research benchmark.

A release tag is not created until all P0 gates pass.

---

# 82. Final SIH Hardware / Software Bill of Materials

## Minimum live demonstration

```text
3 laptops
1 managed Ethernet switch with SPAN/port mirroring
Ethernet cables
```

### Laptop A — SPECTRA sensor/analysis

Preferred:

```text
Linux
2 NICs if possible
Zeek
Python backend
ML artifacts
React dashboard
Docker/Compose as appropriate
```

### Laptop B — controlled traffic source

Runs:

```text
authorized synthetic traffic generator
```

No real malware required.

### Laptop C — simulated production target

Runs harmless test services.

### Optional expansion

Add B2/B3 for distributed-source scenarios. A total of 5 laptops is useful but not required because distributed/spoofed scenarios can be demonstrated safely through prepared PCAPs.

---

# 83. Final SIH Demonstration Runbook

## Minute 0–1: Problem and architecture

Show:

```text
Source → Target
     \ mirrored copy
      → SPECTRA
```

State explicitly:

> “SPECTRA is not inline and does not need a return path to the monitored network.”

## Minute 1–2: Passive proof

Show the SPAN/TAP path and sensor/management interface separation.

## Minute 2–3: Benign traffic

Show normal HTTP/DNS/TLS traffic and baseline metrics.

## Minute 3–4: Port scan

Generate controlled fan-out and show the alert and evidence.

## Minute 4–5: DGA/DNS

Generate or replay controlled suspicious DNS data and show entropy/n-gram/query evidence.

## Minute 5–6: C2

Run a safe periodic-beacon test process. Show inter-arrival/periodicity evidence and the measured evidence-acquisition/alert latency.

## Minute 6–7: TLS

Show encrypted traffic metadata and explicitly state that the payload is not decrypted.

## Minute 7–8: DDoS + exfiltration

Use prepared PCAPs where live generation would require distributed/spoofed/reflection behavior. Show the evidence fields.

## Minute 8–9: Performance

Show:

```text
input packets/sec
flows/sec
Mbps
capture loss
processed events/sec
drops
queue
CPU
RAM
latency P50/P95/P99
```

## Minute 9–10: Incident/evidence story

Show how an alert points back to the source event and model version. If P1 correlation is implemented, show the incident timeline; otherwise show grouped evidence without pretending correlation exists.

---

# 84. Demonstration Failure Tree

The team must rehearse the following fallback paths.

```text
LIVE SENSOR FAILS?
       ↓
Use validated PCAP replay
       ↓

WEBSOCKET FAILS?
       ↓
Show REST alert retrieval
       ↓

MODEL FAILS?
       ↓
Startup validation identifies failed artifact
       ↓
Use PCAP scenario for a validated detector
       ↓

DEMO NETWORK FAILS?
       ↓
Run offline end-to-end replay
       ↓

POWER / MACHINE FAILURE?
       ↓
Use second machine or recorded validated run
```

The emergency recorded demonstration must be honest and labeled as recorded evidence.

---

# 85. Final “Do Not Claim” Rules

Never claim any of the following until the corresponding evidence exists:

- “500 pps sustained end-to-end” without a benchmark;
- “zero packet loss” without capture-layer evidence;
- “real-time” based only on inference latency;
- “full QUIC detection” without a verified QUIC path;
- “all threat classes validated” without the detector acceptance matrix;
- “NIST compliant” or “NIST certified”;
- “data diode” when using only SPAN;
- “confidence = probability” when scores are uncalibrated;
- “the live two-laptop API test proves passive monitoring”;
- “the model works on unseen networks” without cross-dataset/generalization evidence;
- “the model is self-contained” if auxiliary preprocessing artifacts are missing.

---

# 86. Final Traceability Matrix — SIH Statement to Implementation

| SIH requirement | SPECTRA requirement | Evidence required | Release gate |
|---|---|---|---|
| One-directional/read-only ingest | Passive sensor boundary + sensor-plane isolation | topology + interface/egress verification | Gate 8 |
| No return path | Sensor interface cannot route to protected side | network test | Gate 8 |
| No active probes/handshakes | Backend contains no active production interaction path | code review + runtime observation | Gate 1 |
| No payload decryption | TLS/QUIC metadata-only feature paths | code/config review + test | Gate 1 |
| Streaming | Incremental event processing | live/replay timestamped run | Gate 3 |
| Bounded latency | Stage metrics + rolling scoring | P50/P95/P99 report | Gate 4 |
| Defined throughput | packets/s + flows/s + Mbps | sustained benchmark | Gate 5 |
| Threat detection | Required detector matrix | per-detector evaluation | Gate 1/7 |
| Standard alerts | canonical + enhanced alert schema | schema/API tests | Gate 9 |
| Confidence/evidence | score/evidence/lineage contract | alert inspection | Gate 9 |
| Visualization | React/WebSocket dashboard | live alert demo | Gate 10 |
| Reproducibility | scenario + ground-truth runner | machine-readable report | Gate 7/10 |
| Critical infrastructure suitability | passive architecture + OT-aware context | architecture/demo evidence | Gate 8 |

---

# 87. Final Implementation Order — Locked

Do not implement in arbitrary order. Use this sequence.

### Step 1 — Baseline

Run the current repository exactly as-is and record:

```text
commit SHA
model inventory
model checksums
current test status
current replay metrics
hardware/software profile
```

### Step 2 — Contract hardening

Implement:

```text
configuration
model manifests
artifact validation
canonical schemas
MVP alert schema
persistence
```

### Step 3 — Temporal correctness

Implement/test:

```text
reordering
lateness
rolling windows
periodic scoring
flush semantics
```

### Step 4 — Detector correctness

Complete the full detector acceptance matrix.

### Step 5 — Performance instrumentation

Implement stage timestamps and the benchmark harness.

### Step 6 — Live passive sensor

Deploy the Linux reference sensor and prove SPAN/TAP visibility plus absence of sensor-plane return traffic.

### Step 7 — P1 intelligence

Only after P0 is green:

```text
asset registry
expected flows
risk
correlation
incident lifecycle
```

### Step 8 — SIH rehearsal

Run exactly the final demonstration procedure, including failures/fallbacks.

---

# 88. Completeness Audit Before Work Starts

The PRD is considered implementation-complete when every item below has an owner, a test and a pass/fail rule.

```text
[ ] Architecture frozen
[ ] Runtime modes frozen
[ ] Live capture topology frozen
[ ] Sensor/management plane separation defined
[ ] Replay timing modes defined
[ ] Canonical event schema defined
[ ] Time semantics defined
[ ] Event ordering/lateness defined
[ ] Windowing/scoring semantics defined
[ ] Model artifact contract defined
[ ] Ground truth contract defined
[ ] Detector acceptance matrix defined
[ ] Alert schema defined
[ ] Alert deduplication defined
[ ] Evidence persistence defined
[ ] Evidence hashing/lineage defined
[ ] REST contract defined
[ ] WebSocket contract defined
[ ] API security boundaries defined
[ ] Throughput metric definitions defined
[ ] Latency metric definitions defined
[ ] Performance acceptance targets defined
[ ] Capture-loss accounting defined
[ ] Queue overflow behavior defined
[ ] Resource metrics defined
[ ] Failure/recovery behavior defined
[ ] Data retention defined
[ ] Privacy/repository policy defined
[ ] Protocol/address scope defined
[ ] Model reproducibility defined
[ ] Scenario runner defined
[ ] CI/release process defined
[ ] Live demo hardware defined
[ ] PCAP fallback defined
[ ] Emergency fallback defined
[ ] Do-not-claim rules defined
[ ] SIH traceability defined
[ ] Implementation order locked
```

**This checklist is a design-completeness gate, not a claim that every checkbox is already implemented.**

---

# 89. Cross-Verification Record

This version was reconciled against the supplied project materials and the official external references used by the architecture.

## Internal consistency checks performed

- Six SIH threat families are consistently distinguished from seven detector modules.
- Exfiltration is treated as required/P0 rather than optional.
- QUIC is separated from TLS and requires an independently verified path.
- Model scores, calibrated confidence, heuristic scores, risk and severity are distinct concepts.
- SPECTRA event drops are explicitly separated from packet/capture loss.
- PCAP packet rate is explicitly separated from telemetry-event throughput.
- Replay throughput is not presented as network throughput.
- Temporal evidence-acquisition latency is separated from post-evidence processing latency.
- SPAN is explicitly not called a data diode.
- The two-laptop API connectivity test is explicitly not treated as passive packet-monitoring proof.
- P1 capabilities are not required for P0 release unless a later release explicitly promotes them.
- Historical replay results are marked as reference evidence, not final performance claims.
- Mock/test mode is separated from LIVE mode.

## External reference checks

The external standards section uses the current final NIST publications: SP 800-82 Rev. 3 (final), SP 800-94 (final), SP 800-61 Rev. 3 (final), and CSF 2.0. Zeek's documentation was also checked for common logs, capture-loss diagnostics, live interface monitoring and platform support.

---

# 90. Implementation Invariants

The following invariants apply to every final build:

```text
1. LIVE mode never loads MockDetector.
2. LIVE mode never performs active probes or mitigation.
3. Sensor NIC cannot provide a return path toward the protected/test-production side.
4. Every model prediction is traceable to an exact feature schema and artifact version.
5. Every alert is traceable to source telemetry and timestamps.
6. Every performance claim is tied to a recorded workload and reference machine.
7. Packet/capture loss and application-event loss are never conflated.
8. Raw model probability and calibrated confidence are never conflated.
9. A PCAP replay result is never presented as proof of live network throughput.
10. A SPAN demonstration is never presented as a hardware data diode.
11. A successful API connection is never presented as proof of passive packet visibility.
12. No final demo depends on real malware or uncontrolled external traffic.
```

---

# 91. Final Definition of Done — Version 3.0

SPECTRA is ready for SIH release only when all of the following are simultaneously true:

```text
PASSIVE BOUNDARY PROVEN
        ↓
READ-ONLY / NO RETURN PATH PROVEN
        ↓
ZEEK LIVE + PCAP INPUT WORKS
        ↓
ALL REQUIRED DETECTORS HAVE VALIDATED EXECUTION PATHS
        ↓
MODEL + PREPROCESSING + FEATURE CONTRACTS ARE REPRODUCIBLE
        ↓
TEMPORAL ORDERING / LATENESS IS CORRECT
        ↓
CAPTURE LOSS IS MEASURED
        ↓
THROUGHPUT IS MEASURED
        ↓
CAPTURE→ALERT LATENCY IS MEASURED
        ↓
QUEUE / CPU / RAM BEHAVIOR IS MEASURED
        ↓
ALERTS CONTAIN EVIDENCE + LINEAGE
        ↓
FALSE-POSITIVE / DETECTION QUALITY IS EVALUATED
        ↓
LIVE DEMO WORKS
        ↓
PCAP FALLBACK WORKS
        ↓
ALL P0 RELEASE GATES PASS
```

At this point, the team should **stop redesigning the architecture for presentation purposes** and work only against the implementation order, acceptance matrix and release gates unless a test reveals a real architectural defect.

---

# 92. Version 3.0 Change Log

## Added

- exact runtime modes;
- replay timing contract;
- ground-truth schema;
- persistent evidence contract;
- alert deduplication/storm control;
- live sensor reference architecture;
- sensor/management plane separation;
- capture-loss accounting contract;
- clock/timestamp contract;
- artifact security and manifest validation;
- API/management security boundaries;
- retention/privacy policy;
- exact P0 performance targets;
- detector acceptance matrix;
- confidence/risk/severity separation;
- configuration contract;
- reproducible scenario runner;
- CI/release requirements;
- hardware/software demonstration BOM;
- final SIH runbook and fallback tree;
- SIH traceability matrix;
- completeness checklist;
- cross-verification record.

## Corrected

- historical replay throughput is no longer presented as network throughput;
- SPECTRA event drops are no longer conflated with packet/capture loss;
- SPAN is explicitly distinguished from a hardware data diode;
- the two-laptop API test is explicitly distinguished from passive capture proof;
- exfiltration is treated as required;
- TLS and QUIC are separate validation paths;
- calibrated confidence is not assumed from raw model probability;
- correlation/incident capabilities remain P1 unless deliberately promoted;
- Windows is not treated as the preferred live Zeek sensor platform.


# 93. Preflight and Health Contract

Before every live demonstration or release benchmark, SPECTRA must run a preflight check and produce a human-readable PASS/FAIL summary.

## 93.1 Preflight checks

```text
[ ] Correct git commit / release ID
[ ] Correct runtime mode
[ ] Python/runtime dependencies compatible
[ ] Zeek available and version recorded
[ ] Required capture interface exists
[ ] Required Zeek scripts/configuration present
[ ] Required model artifacts present
[ ] All model checksums valid
[ ] All feature schemas present
[ ] All preprocessors/auxiliary artifacts present
[ ] Smoke inference succeeds for every enabled detector
[ ] Evidence store writable/readable
[ ] Retention/storage capacity acceptable
[ ] Backend port available
[ ] WebSocket endpoint reachable from dashboard
[ ] Sensor interface has no protected-side return route
[ ] Management interface reachable only from demo/management network
[ ] Required test fixture/ground-truth manifest available for replay mode
```

A failed P0 preflight check blocks the final demo/benchmark unless the failure is explicitly documented as a non-applicable check for that mode.

## 93.2 Health endpoint contract

`GET /health` must expose enough information to distinguish:

```text
service_started
service_ready
worker_alive
model_validation_ok
storage_ok
capture_connected (live mode)
mode
```

Health state must not report `ready=true` when a required worker/model/storage dependency is known to be unusable.

`GET /stats` remains the detailed operational metrics endpoint.

---

# 94. Ownership and Execution Control

Each P0 area must have one accountable owner on the project team, even when multiple people contribute.

| Workstream | Accountable role | Required evidence |
|---|---|---|
| Passive network/capture | Network lead | topology + capture-loss report |
| Zeek integration | Telemetry lead | Zeek logs + ingest test |
| Runtime/windowing | Backend lead | ordering/window tests + latency report |
| Detector integration | ML integration lead | feature/model contract matrix |
| ML evaluation | ML lead | model cards + labeled evaluation reports |
| Evidence/storage | Backend/security lead | persistence + hash/restore test |
| API/WebSocket | Backend/API lead | contract + live delivery test |
| Dashboard | Frontend lead | live alert demonstration |
| Docker/deployment | DevOps lead | clean deployment test |
| SIH benchmark | Test lead | signed/approved benchmark report |
| SIH demo | Demo lead | complete rehearsal + fallback proof |

The exact person assigned to each role is a team decision; the role itself must exist before Phase 1 implementation begins.

---

# 95. Final Cross-Verification Checklist

Before the first “final” SIH release build, the team must run this checklist against the repository and generated evidence—not merely against this document.

## Requirement consistency

```text
[ ] Problem statement matches implementation scope
[ ] Six threat families / seven detector-module terminology is consistent
[ ] Exfiltration is P0 and not optional
[ ] TLS and QUIC are separately verified
[ ] Read-only/passive claim is separated from API connectivity
[ ] SPAN is not called a data diode
[ ] PCAP rate is not called sustained live throughput
[ ] SPECTRA event drops are not called packet loss
[ ] Raw model score is not called calibrated confidence
[ ] Historical baseline numbers are not used as final acceptance evidence
```

## Measurement consistency

```text
[ ] Capture timestamp exists
[ ] Zeek/log availability timestamp exists where measurable
[ ] Ingestion timestamp exists
[ ] Feature-ready timestamp exists
[ ] Inference timestamps exist
[ ] Alert-created timestamp exists
[ ] Dashboard-delivery timestamp exists
[ ] Monotonic duration measurement is used for local latency
[ ] Multi-host clock policy is documented
[ ] P50/P95/P99/MAX are calculated
[ ] Evidence-acquisition latency is separated from processing latency
```

## Reproducibility consistency

```text
[ ] Git SHA recorded
[ ] Hardware profile recorded
[ ] OS recorded
[ ] Python version recorded
[ ] Zeek version recorded
[ ] Model versions/checksums recorded
[ ] Configuration version/hash recorded
[ ] Replay mode recorded
[ ] Fixture ID recorded
[ ] Ground-truth manifest recorded
[ ] Machine-readable report generated
```

## Security consistency

```text
[ ] No real malware required for demonstration
[ ] Demo traffic stays inside authorized lab network
[ ] Sensor plane has no protected-side return route
[ ] Management plane is separate
[ ] LIVE mode cannot load mocks
[ ] Untrusted model artifacts are rejected
[ ] Sensitive real-world captures are not committed to public repositories
```

A release is blocked if any P0 consistency check fails.

---

# 96. Final Start Decision

With Version 3.0 of this PRD, the engineering team has a frozen architecture, explicit operating modes, defined interfaces, measurable performance criteria, detector-specific validation requirements, passive-boundary requirements, storage/forensic requirements, demonstration topology, fallback strategy, and release gates.

**There is no intentionally unresolved major design question remaining in this PRD.** Values that depend on measurement are explicitly treated as benchmark outputs, not assumptions.

The next action is implementation and verification—not another architecture rewrite.
