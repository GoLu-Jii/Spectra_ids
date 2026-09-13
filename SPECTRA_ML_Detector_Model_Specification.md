# SPECTRA — ML Detector & Model Integration Specification
## Research-Backed Requirements for the Six SIH Threat Families

**Document purpose:** This document defines what each threat-detection model in SPECTRA is expected to do, what data it should be trained on, what features it should consume, what it should return to the backend, how it should be evaluated, and what must be true before that detector is considered production-ready for the SIH prototype.

**Scope:** Six SIH threat families, implemented internally through modular detector paths:
1. DDoS
2. C2 Beaconing
3. DGA / DNS Threats
4. Malware in TLS / QUIC encrypted sessions
5. Reconnaissance / Port Scanning
6. Data Exfiltration

> **Important:** A model is not considered complete merely because a `.pkl`, `.joblib`, or `.json` artifact exists. A detector is complete only when its feature construction, preprocessing, model artifact, threshold, evidence generation, adapter, validation dataset, evaluation results, and runtime integration are reproducible.

---

# 1. Core Design Principle

The central ML rule for SPECTRA is:

```text
TRAINING INPUT
    =
PRODUCTION INFERENCE INPUT
```

The model must be trained using the same observable feature semantics that the monitoring enclave will provide at runtime.

The following is NOT acceptable:

```text
Training:
CICFlowMeter / rich offline features
        ↓
Model

Runtime:
Zeek / different features
        ↓
Model
```

The correct design is:

```text
Training PCAP
     ↓
Zeek / equivalent telemetry
     ↓
SPECTRA feature builder
     ↓
Training feature matrix
     ↓
Model
```

and:

```text
Live passive traffic
     ↓
Zeek
     ↓
SPECTRA feature builder
     ↓
Same feature schema
     ↓
Same model
```

This prevents training/serving feature skew.

---

# 2. Passive-Observation Constraint

SPECTRA operates in a monitoring enclave and must use only information available from passive observation.

Allowed inputs include:

- packet captures
- network flow records
- Zeek-derived metadata
- DNS metadata
- TLS metadata
- QUIC metadata where actually available
- timestamps
- packet/byte statistics
- protocol metadata
- connection/flow behavior

The detector must NOT depend on:

- active probes
- active scanning
- sending a handshake to the observed endpoint
- returning a mitigation command
- modifying production traffic
- inline blocking
- decrypting TLS/QUIC application payloads

The model therefore needs to be designed around **observable network metadata**, not unavailable payload content.

---

# 3. Common ML-to-Backend Contract

Every detector adapter must normalize model output into a common `Prediction` contract.

Recommended structure:

```python
class Prediction:
    status: Literal[
        "DETECTED",
        "BENIGN",
        "INSUFFICIENT_CONTEXT",
        "REVIEW",
        "ERROR"
    ]

    threat_class: str

    score_type: Literal[
        "probability",
        "anomaly"
    ]

    raw_score: float | None
    threshold: float | None

    evidence: dict
    context: dict

    detector_name: str
    detector_version: str

    model_name: str
    model_version: str

    feature_schema: str
```

### Meaning of statuses

**DETECTED**
- Evidence is sufficient.
- Model/decision rule crossed the documented threshold.

**BENIGN**
- Evidence is sufficient.
- Model score is below the decision threshold.

**INSUFFICIENT_CONTEXT**
- Not enough observations have been collected for this detector.
- This is especially important for temporal detectors such as C2.

**REVIEW**
- Evidence is ambiguous, unstable, out-of-distribution, or otherwise requires analyst attention.

**ERROR**
- Detector could not perform inference safely.

A detector should never silently convert missing evidence into zero-filled malicious/benign evidence unless the model contract explicitly specifies that behavior.

---

# 4. Final Backend Alert Contract

The ML model should NOT decide operational fields such as asset criticality, analyst status, or incident ID.

The backend should add those fields.

Minimum SIH-required fields:

```json
{
  "alert_id": "ALT-...",
  "timestamp": "...",
  "flow_id": "...",
  "threat_class": "DDoS",
  "confidence": 0.91,
  "evidence": {}
}
```

Recommended production alert:

```json
{
  "alert_id": "ALT-...",
  "incident_id": null,
  "observed_at": "...",
  "alert_created_at": "...",
  "delivered_at": "...",

  "flow_id": "...",
  "asset_id": null,

  "src_ip": "...",
  "src_port": 0,
  "dst_ip": "...",
  "dst_port": 0,
  "protocol": "TCP",

  "threat_class": "DDoS",
  "severity": "HIGH",

  "raw_model_probability": 0.94,
  "calibrated_confidence": null,
  "heuristic_score": null,
  "risk_score": null,

  "model": "ddos_xgb",
  "model_version": "1.0",
  "feature_schema": "ddos-v1",

  "evidence": {},
  "evidence_hash": null,

  "status": "NEW"
}
```

### Critical rule

Do not represent:

- a heuristic score as a model probability;
- an anomaly score as a calibrated probability;
- an uncalibrated classifier score as an absolute probability statement.

Keep these separate:

```text
raw_model_probability
calibrated_confidence
heuristic_score
combined_risk_score
```

---

# 5. Detector 1 — DDoS

## 5.1 Required SIH behavior

The detector must cover:

- SYN floods
- UDP reflection/amplification-like attacks
- spoofed-source floods

The system should analyze:

- flow-level rate
- packet rate
- byte rate
- TCP flag behavior
- source diversity
- source-IP entropy
- destination concentration
- protocol behavior
- bidirectional/asymmetry statistics

A high packet rate alone must NOT be considered sufficient evidence.

## 5.2 Recommended datasets

### Primary training source
**CIC-DDoS2019**

Provides DDoS traffic across multiple attack categories and includes PCAP/flow resources.

### External validation source
**CIC-IDS2017**

Useful as a separate evaluation environment and contains network attack and benign traffic, including DoS/DDoS-related scenarios.

### Why two datasets?

The final evaluation should distinguish:

```text
within-dataset performance
```

from:

```text
cross-dataset generalization
```

## 5.3 Recommended model

Start with:

```text
Baseline:
Logistic Regression

Tree baselines:
Random Forest
XGBoost / LightGBM
```

Select based on:

- F1
- Recall
- False Positive Rate
- latency
- model size
- stability

Do not choose a more complex model only because it is newer.

## 5.4 Feature set

At minimum:

```text
duration
total_packets
total_bytes
orig_packets
resp_packets
orig_bytes
resp_bytes

packets_per_second
bytes_per_second
average_packet_size

syn_count
ack_count
rst_count
fin_count

syn_ratio
ack_ratio
rst_ratio

unique_source_ips
source_ip_entropy

unique_destination_ips
flows_per_destination
packets_per_destination
bytes_per_destination

protocol_distribution
direction_distribution

bidirectional_ratio
```

The exact final feature vector must be versioned and frozen.

## 5.5 Model output

```json
{
  "status": "DETECTED",
  "threat_class": "DDoS",
  "subtype": "SYN_FLOOD",
  "score_type": "probability",
  "raw_score": 0.94,
  "threshold": 0.80,
  "evidence": {
    "packets_per_second": 8210,
    "syn_ratio": 0.96,
    "unique_source_ips": 1832,
    "source_ip_entropy": 0.41,
    "flows_per_destination": 912
  }
}
```

## 5.6 Required validation

Minimum:

```text
SYN flood
UDP reflection/amplification-like
spoofed-source simulation
benign high-volume traffic
legitimate burst traffic
```

---

# 6. Detector 2 — Botnet C2 Beaconing

## 6.1 Required SIH behavior

C2 must be treated as a **temporal behavior-detection problem**.

The detector should identify:

- fixed periodic beaconing
- jittered beaconing
- low-and-slow beaconing
- repeated destination communication
- temporal persistence

A single flow should normally be insufficient to claim C2.

## 6.2 Recommended datasets

### Primary
**CTU-13**

Contains real botnet scenarios with botnet, normal and background traffic and is useful for behavioral/temporal evaluation.

### Additional validation
Use held-out scenarios and dedicated controlled beacon fixtures.

## 6.3 Recommended model

Start with:

```text
Random Forest
XGBoost
LightGBM
```

The input is an aggregated chronological sequence converted to statistical features.

A recurrent neural network is not automatically necessary. Begin with robust temporal feature engineering.

## 6.4 Required temporal features

At minimum, where compatible with the training dataset:

```text
flow_count

iat_mean
iat_median
iat_std
iat_variance
iat_cv
iat_min
iat_max

duration_mean
duration_std

bytes_mean
bytes_std
bytes_rate

packets_mean
packets_std

destination_count
destination_repetition
destination_port_entropy

periodicity_score
autocorrelation
burstiness

directionality
reverse_flow_presence
```

## 6.5 Input format

The detector should receive a chronologically ordered sequence such as:

```json
[
  {
    "start_time": 1760000000.0,
    "bytes": 412,
    "packets": 6,
    "dst_ip": "...",
    "dst_port": 443
  },
  {
    "start_time": 1760000030.1,
    "bytes": 398,
    "packets": 6,
    "dst_ip": "...",
    "dst_port": 443
  }
]
```

The adapter should:

1. group compatible flows;
2. order by observed timestamp;
3. compute the exact model feature schema;
4. invoke the model;
5. return a common `Prediction`.

## 6.6 Important latency rule

C2 detection latency includes:

```text
time required to collect enough evidence
+
processing latency
```

Therefore a C2 detector must not be marketed as “instantaneous” merely because inference takes milliseconds.

## 6.7 Required fixtures

```text
fixed 10-second beacon
fixed 30-second beacon
5–10% jittered beacon
20–30% jittered beacon
low-and-slow beacon
multiple destinations
legitimate periodic service
legitimate software update behavior
```

## 6.8 Example output

```json
{
  "status": "DETECTED",
  "threat_class": "C2",
  "score_type": "probability",
  "raw_score": 0.91,
  "threshold": 0.20,
  "evidence": {
    "flow_count": 14,
    "iat_mean": 30.1,
    "iat_std": 1.2,
    "iat_cv": 0.039,
    "destination_repetition": 0.93,
    "periodicity_score": 0.91,
    "burstiness": 0.08
  },
  "context": {
    "observations": 14,
    "window_seconds": 300
  }
}
```

---

# 7. Detector 3 — DGA

## 7.1 What it detects

DGA detection answers:

> Does this queried domain look algorithmically generated?

This is different from DNS tunnelling.

## 7.2 Recommended dataset

### Primary
**ExtraHop DGA Detection Training Dataset**

Large domain corpus with benign/DGA labels and millions of samples.

### External validation
Use independent DGA sources such as DGArchive and an independent benign domain source such as popular/trusted-domain lists.

The purpose is to test whether the classifier learned general lexical structure rather than the quirks of one corpus.

## 7.3 Recommended model

```text
XGBoost / LightGBM
```

with a Logistic Regression baseline if desired.

## 7.4 Features

Base lexical features:

```text
full_domain_length
sld_length
tld_length
entropy
digit_ratio
vowel_ratio
consonant_ratio
vowel_consonant_ratio
unique_character_ratio
dictionary_match_ratio
```

Character n-grams:

```text
character bigrams
character trigrams
```

If a TF-IDF vectorizer is used, it is part of the deployable model artifact.

## 7.5 Input

The detector can operate at query/domain level:

```text
DNS query
    ↓
extract domain
    ↓
normalize
    ↓
feature builder
    ↓
model
```

No 60-second flow window is required for the basic lexical DGA decision.

## 7.6 Required artifact package

```text
dga/
├── model.*
├── vectorizer.*
├── dictionary.*
├── feature_schema.json
├── config.yaml
├── model_card.md
└── checksum.sha256
```

A model that silently depends on an external vectorizer or dictionary is incomplete.

## 7.7 Required validation

```text
normal domains
CDN/cloud domains
short random-looking benign names
generated malicious domains
mixed DNS traffic
```

## 7.8 Example output

```json
{
  "status": "DETECTED",
  "threat_class": "DGA",
  "score_type": "probability",
  "raw_score": 0.97,
  "threshold": 0.50,
  "evidence": {
    "domain": "xj29skd91a",
    "entropy": 4.31,
    "digit_ratio": 0.22,
    "unique_character_ratio": 0.91,
    "ngram_score": 0.94
  }
}
```

---

# 8. Detector 4 — DNS Tunnelling

## 8.1 What it detects

DNS tunnelling asks:

> Does the DNS traffic behave like a covert data channel?

This is NOT the same as DGA.

DGA is mainly lexical.

DNS tunnelling requires:

```text
lexical evidence
+
volume evidence
+
temporal evidence
```

## 8.2 Research source

**DNSTunnel2026** is a useful recent research dataset for understanding realistic DNS tunnelling features. It contains tens of millions of benign samples and over thirty thousand tunnelling samples, with aggregated statistical features and multiple tunnelling scenarios.

However, do not blindly use a feature schema that depends on information unavailable to SPECTRA at runtime.

The production feature schema must be built from locally observable passive DNS metadata.

## 8.3 Recommended production feature groups

### Lexical

```text
query_length
entropy
unique_subdomain_ratio
character_distribution
```

### Volume

```text
query_frequency
request_bytes
response_bytes
request_response_ratio
record_type_distribution
TXT_ratio
NXDOMAIN_ratio
```

### Temporal

```text
inter_arrival_mean
inter_arrival_std
inter_arrival_cv
burstiness
queries_per_window
```

### Context

```text
resolver
destination
queried_domain
unique_queries
repetition
```

## 8.4 Aggregation requirement

The pipeline must explicitly implement:

```text
DNS events
   ↓
session/query grouping
   ↓
statistical aggregation
   ↓
feature vector
   ↓
model
```

There must be no undocumented upstream feature-builder dependency.

## 8.5 Recommended model

```text
XGBoost / LightGBM
```

Potentially add:

```text
Isolation Forest
```

as a secondary anomaly signal for previously unseen/low-and-slow behavior.

## 8.6 Example output

```json
{
  "status": "DETECTED",
  "threat_class": "DNS_TUNNEL",
  "score_type": "probability",
  "raw_score": 0.93,
  "threshold": 0.50,
  "evidence": {
    "query_frequency": 81,
    "mean_query_length": 57,
    "entropy": 4.8,
    "nxdomain_ratio": 0.72,
    "txt_ratio": 0.64,
    "outbound_query_bytes": 38200
  }
}
```

---

# 9. Detector 5 — Malware in TLS / QUIC Encrypted Sessions

## 9.1 Required behavior

The detector must infer suspicious encrypted-session behavior from metadata.

It must NOT decrypt application payloads.

The project should expose this as one threat family with separate internal paths:

```text
Encrypted Traffic
       │
       ├── TLS path
       │
       └── QUIC path
```

Do not call the QUIC path “validated supervised malware classification” unless a real labeled training/evaluation corpus is available.

## 9.2 TLS dataset

### Recommended primary
**USTC-TFC2016**

Contains labeled malware and benign application traffic in PCAP form.

Correct processing:

```text
PCAP
 ↓
metadata extraction only
 ↓
TLS session features
 ↓
model
```

No payload bytes should be used by the detector.

## 9.3 Observable feature families

Potential features:

```text
TLS version
cipher information
extensions
SNI where visible
ALPN
certificate metadata
JA3 where available
JA3S where available
JA4 where available

connection duration
bytes
packets

packet-size statistics
timing statistics
directionality
session behavior
```

Not every feature will be visible in every deployment, therefore the final schema must be tied to actual Zeek/capture capabilities.

## 9.4 Exact feature contract

If the selected artifact expects 37 features:

```text
exactly those 37
```

must be produced.

Not:

```text
34 + three invented zeros
```

Not:

```text
36 plus a placeholder
```

Not:

```text
"close enough"
```

If the feature schema changes, retraining/revalidation is required.

## 9.5 QUIC

Zeek provides QUIC-related telemetry, but the availability of metadata is not equivalent to having a labeled QUIC-malware training corpus.

Therefore the recommended approach is:

```text
TLS:
supervised metadata classifier

QUIC:
separate observable feature path
+
controlled suspicious/benign validation
+
anomaly detection until a defensible labeled corpus exists
```

## 9.6 Robustness

Where implemented, evasion testing may perturb the feature vector and check prediction stability.

Important outputs:

```text
raw probability
robust probability
instability score
baseline outlier score
review decision
```

Do not collapse these into one unexplained probability.

## 9.7 Example output

```json
{
  "status": "REVIEW",
  "threat_class": "ENCRYPTED_MALWARE",
  "score_type": "probability",
  "raw_score": 0.71,
  "threshold": 0.80,
  "evidence": {
    "tls_version": "TLS1.3",
    "ja4": "...",
    "packet_size_variance": 18.2,
    "iat_cv": 0.42,
    "session_duration": 94.4
  },
  "context": {
    "protocol_family": "TLS",
    "evasion_instability": 0.17,
    "baseline_ready": true
  }
}
```

---

# 10. Detector 6 — Reconnaissance / Port Scanning

## 10.1 Required behavior

Detect:

### Vertical scanning

One source:

```text
source → many ports
```

### Horizontal scanning

One source:

```text
source → many hosts
```

Potential scanning evidence:

```text
unique_destination_ports
unique_destination_hosts
connection_count
fanout_rate
failed_connection_ratio
unanswered_connections
SYN behavior
duration statistics
destination-port entropy
```

## 10.2 Recommended datasets

### Primary
**CIC-IDS2017**

Contains explicit PortScan scenarios and benign traffic.

### External
**UNSW-NB15**

Includes reconnaissance as an attack class.

Optional additional validation:
**IoTID20**

## 10.3 Model

```text
Logistic Regression baseline
Random Forest
XGBoost / LightGBM
```

## 10.4 Important scoring rule

Keep:

```text
model_probability
```

separate from:

```text
heuristic_score
```

If a heuristic says:

```text
unique_ports = 50
```

do not report:

```text
confidence = 0.85
```

unless that number has a clearly defined statistical meaning.

## 10.5 Example output

```json
{
  "status": "DETECTED",
  "threat_class": "RECON",
  "subtype": "VERTICAL_PORT_SCAN",
  "score_type": "probability",
  "raw_score": 0.96,
  "threshold": 0.80,
  "evidence": {
    "unique_destination_ports": 43,
    "unique_destination_hosts": 1,
    "connection_count": 61,
    "failed_connection_ratio": 0.91,
    "fanout_rate": 38.4
  }
}
```

---

# 11. Detector 7 — Data Exfiltration

## 11.1 Required SIH behavior

Exfiltration is a required threat family.

Detect:

- outbound/inbound byte asymmetry
- large outbound transfers
- abnormal destination behavior
- unusual flow duration/rate
- temporal persistence

## 11.2 Recommended dataset

### Primary
**BoT-IoT**

Contains PCAP/flow data and explicitly includes data-exfiltration attack scenarios alongside DDoS, DoS, scanning and other categories.

## 11.3 Recommended model

```text
XGBoost / LightGBM
```

with behavioral baseline support where useful.

## 11.4 Feature groups

```text
outbound_bytes
inbound_bytes
outbound_inbound_ratio

outbound_packets
inbound_packets
packet_ratio

flow_duration
outbound_bytes_per_second
inbound_bytes_per_second

destination_novelty
destination_count
connection_count

temporal_persistence
repetition
burstiness
```

## 11.5 Example output

```json
{
  "status": "DETECTED",
  "threat_class": "EXFILTRATION",
  "score_type": "probability",
  "raw_score": 0.89,
  "threshold": 0.80,
  "evidence": {
    "outbound_bytes": 18200000,
    "inbound_bytes": 320000,
    "outbound_inbound_ratio": 56.9,
    "destination_novelty": 0.91,
    "duration_seconds": 420
  }
}
```

---

# 12. Dataset Strategy

Recommended baseline:

| Threat | Primary training | External / independent validation |
|---|---|---|
| DDoS | CIC-DDoS2019 | CIC-IDS2017 |
| C2 | CTU-13 | held-out botnet scenarios + controlled temporal fixtures |
| DGA | ExtraHop DGA dataset | DGArchive + independent benign domains |
| DNS tunnelling | DNSTunnel2026 + controlled tunnel traffic | separate tunnel corpus |
| TLS malware | USTC-TFC2016 | held-out malware/application traffic |
| QUIC | controlled benign + suspicious QUIC | independent controlled validation |
| Recon | CIC-IDS2017 | UNSW-NB15 / IoTID20 |
| Exfiltration | BoT-IoT | controlled low-and-slow scenarios |

### Important

The six SIH threat families can therefore be implemented with more than six internal model components.

That is intentional:

```text
6 threat families
       ↓
modular detector paths
```

---

# 13. Training / Validation / Test Methodology

Avoid simple random row splitting when flows from the same attack campaign are strongly correlated.

Prefer:

```text
scenario-aware split
host/source-aware split
time-aware split
dataset-aware external test
```

Example:

```text
Training:
CTU scenarios A–H

Validation:
CTU scenarios I–J

Internal test:
CTU scenarios K–L

External test:
independent dataset/fixture
```

The exact split must be documented per detector.

---

# 14. Required ML Metrics

Every supervised detector must report:

```text
Precision
Recall
F1
False Positive Rate
False Negative Rate
ROC-AUC
PR-AUC
Confusion Matrix
```

Also record:

```text
threshold
average inference latency
P95 inference latency
model size
feature count
```

For streaming detection, additionally record:

```text
capture→alert latency
evidence-acquisition latency
queue delay
```

For anomaly models, report anomaly-specific metrics and explain score semantics.

---

# 15. Calibration

If the UI says:

```text
Confidence: 91%
```

the underlying score should have a justified interpretation.

Otherwise show:

```text
Model score: 0.91
```

rather than pretending it is a calibrated probability.

Where calibration is used, document:

```text
calibration method
validation set
calibration metric
calibrated confidence
```

Potential metrics:

```text
Brier score
ECE
reliability curve
```

---

# 16. Threshold Selection

Thresholds must be learned/documented from validation data, not arbitrary constants.

For each model:

```text
raw score distribution
      ↓
validation analysis
      ↓
threshold selection
      ↓
FPR / FNR trade-off
      ↓
documented threshold
```

Thresholds must be versioned.

Example:

```yaml
threshold:
  value: 0.82
  method: validation_fpr_target
  validation_dataset: CIC-DDoS2019-validation-v2
```

---

# 17. Model Artifact Packaging

Every detector must be self-contained.

Recommended:

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
    checksum.sha256

  dns_tunnel/
    model.*
    preprocessor.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  tls/
    model.*
    preprocessor.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  quic/
    model.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  recon/
    model.*
    preprocessor.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256

  exfiltration/
    model.*
    preprocessor.*
    feature_schema.json
    config.yaml
    model_card.md
    checksum.sha256
```

---

# 18. Required Model Manifest

Every artifact package must declare:

```yaml
model_name:
model_version:

framework:
framework_version:
python_version:

feature_schema:
preprocessor_version:

threshold:
threshold_method:

training_dataset:
training_dataset_version:
training_date:

evaluation_report:

artifact_checksum:
```

Optional but strongly recommended:

```yaml
expected_input:
expected_output:
latency_profile:
known_limitations:
owner:
license:
```

---

# 19. Model Card Requirements

Every detector needs:

```text
Model name
Version

Threat family
Threat subtype

Training dataset
Dataset license
Dataset source
Dataset limitations

Feature schema
Preprocessing
Window semantics
Scoring cadence

Train split
Validation split
Test split
External test

Threshold

Precision
Recall
F1
FPR
FNR
PR-AUC
ROC-AUC

Inference latency
Model size

Known failure modes
Known blind spots
Expected deployment environment
```

---

# 20. Window and Temporal Semantics

The detector context and scoring interval are separate concepts.

Example:

```text
context window = 60 seconds
scoring interval = 1 second
```

This is acceptable only if the model feature semantics remain compatible.

The critical rule is:

```text
training context semantics
        =
inference context semantics
```

Do not take a model trained on:

```text
5-second tumbling buckets
```

and silently deploy it on:

```text
60-second rolling windows
```

without retraining/revalidation.

---

# 21. Event Ordering

Temporal detectors need timestamp-aware processing.

Recommended:

```text
Incoming telemetry
       ↓
Reorder buffer
       ↓
Timestamp-ordered events
       ↓
Window / detector
```

Define:

```text
maximum lateness
buffer capacity
late-event policy
quarantine policy
metrics
```

For example:

```text
within lateness bound
    → reorder/process

outside bound
    → mark late
    → process according to defined policy
      OR quarantine
    → increment late_event metric
```

Use:

```text
UTC-aware wall-clock timestamps
```

for evidence and:

```text
monotonic timers
```

for local duration measurements.

---

# 22. Latency Requirements

Do not report only:

```text
model inference = 8 ms
```

Measure:

```text
observed_at
ingested_at
feature_ready_at
inference_started_at
inference_finished_at
alert_created_at
delivered_at
```

Then report:

```text
capture → alert
capture → dashboard
```

at:

```text
P50
P95
P99
MAX
```

Break latency into:

```text
capture/Zeek
ingestion
queue
window/evidence acquisition
feature extraction
inference
alert generation
WebSocket delivery
```

### For temporal detectors

Report both:

```text
evidence-acquisition latency
```

and:

```text
post-evidence processing latency
```

---

# 23. Throughput Requirements

The project must not claim “500 pps support” simply because a 500-pps PCAP was generated.

Report separately:

```text
packets/sec
flows/sec
Mbps
Zeek events/sec
SPECTRA telemetry events/sec
```

A benchmark should include:

```text
500 pps
1,000 pps
5,000 pps
10,000 pps
...
```

or other rates appropriate for the reference hardware.

Each benchmark records:

```text
input rate
processed rate
dropped events
capture loss
queue peak
CPU
RAM
P50/P95/P99 latency
```

---

# 24. Packet Loss vs Application/Event Loss

These are separate metrics.

Correct chain:

```text
Network packets
      ↓
Capture layer
      ↓
Zeek capture loss
      ↓
Zeek records
      ↓
SPECTRA received events
      ↓
SPECTRA processed events
      ↓
Alerts
```

Therefore:

```text
SPECTRA dropped_events = 0
```

does not prove:

```text
packet capture loss = 0
```

Capture-loss statistics must be collected independently.

---

# 25. Hard-Negative Testing

Every detector must be tested against difficult benign behavior.

Examples:

### DDoS
- legitimate high-volume transfers
- backups
- streaming
- bursty services

### C2
- legitimate periodic polling
- telemetry agents
- software update clients

### DGA
- CDN domains
- cloud domains
- random-looking legitimate names

### DNS tunnelling
- legitimate long queries
- TXT-heavy services
- DNS-heavy applications

### TLS
- browsers
- cloud APIs
- update services
- modern TLS1.3 applications

### Recon
- legitimate vulnerability scanners
- service discovery
- monitoring systems

### Exfiltration
- cloud backups
- large legitimate uploads
- database replication

False-positive engineering is mandatory.

---

# 26. Detector Completion Criteria

A detector is complete only when all of the following are true:

```text
[ ] Dataset identified
[ ] Dataset license/provenance recorded
[ ] Label definition documented
[ ] Feature schema frozen
[ ] Feature builder implemented
[ ] Preprocessing packaged
[ ] Model trained
[ ] Validation performed
[ ] Threshold justified
[ ] External/independent validation performed
[ ] Hard-negative validation performed
[ ] Model artifact packaged
[ ] Auxiliary artifacts packaged
[ ] Runtime version pinned
[ ] Adapter implemented
[ ] Prediction contract satisfied
[ ] Evidence generated
[ ] Unit tests pass
[ ] Integration tests pass
[ ] End-to-end replay passes
[ ] Latency measured
[ ] Failure behavior tested
[ ] Model card completed
[ ] Checksum verified
```

---

# 27. Current Known SPECTRA Risks This Specification Is Intended to Eliminate

Previous project audits identified real integration issues including:

- C2 model expecting 23 features while an older wrapper supplied 8.
- DGA requiring a fitted TF-IDF vectorizer and dictionary that were not bundled.
- DNS tunnelling requiring a hidden upstream 29-feature aggregation path.
- TLS requiring an exact 37-feature schema.
- Several model artifacts showing serialization/version compatibility problems.
- Detector implementations returning different types instead of one standardized prediction contract.
- DDoS scaler/model threshold inconsistencies across artifacts/code.
- Internal detector windows conflicting with shared runtime windows.
- Out-of-order events potentially corrupting temporal statistics.
- Protocol schema being too restrictive for all telemetry types.

These are not theoretical risks. They must be treated as engineering acceptance items.

---

# 28. Recommended Final Detector Architecture

```text
                    Zeek Telemetry
                          │
                          ▼
                   Normalized Event
                          │
                          ▼
                   Detector Router
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
      DDoS              C2               Recon
        │                 │                 │
        ▼                 ▼                 ▼
     Feature           Temporal          Feature
     Builder           Builder           Builder
        │                 │                 │
        ▼                 ▼                 ▼
      Model             Model             Model

        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
      DGA            DNS Tunnel         TLS / QUIC
        │                 │                 │
        ▼                 ▼                 ▼
     Feature          Aggregator       TLS/QUIC
     Builder          + Features       Feature Path
        │                 │                 │
        ▼                 ▼                 ▼
      Model             Model             Model

                       +
                   Exfiltration
                       │
                       ▼
                    Feature
                    Builder
                       │
                       ▼
                     Model

                          │
                          ▼
                 Common Prediction
                          │
                          ▼
                  Alert Generator
                          │
                          ▼
              Risk / Correlation Layer
                          │
                          ▼
                   REST / WebSocket
                          │
                          ▼
                    Dashboard
```

---

# 29. What the Models Should NOT Do

Do not put these decisions inside the raw ML model:

```text
asset criticality
incident ID
analyst assignment
dashboard formatting
HTTP/WebSocket handling
MITRE visualization
final operational severity policy
```

The model predicts.

The backend interprets and operationalizes.

Correct separation:

```text
MODEL
What does the traffic look like?

BACKEND
What does that prediction mean operationally?

CORRELATION/RISK
How important is it in context?

DASHBOARD
How should an analyst see it?
```

---

# 30. Required Research Sources

The following sources are recommended as the research baseline for detector development and documentation:

### DDoS / IDS
- University of New Brunswick — CIC-DDoS2019
- University of New Brunswick — CIC-IDS2017

### C2 / Botnet
- CTU / Stratosphere — CTU-13
- Recent research on temporal beaconing and flow-inter-arrival analysis

### DGA
- ExtraHop DGA Detection Training Dataset
- DGArchive / independent domain corpora
- Recent DGA generalization research

### DNS Tunnelling
- DNSTunnel2026 dataset
- Recent DNS tunnelling detection research

### TLS / encrypted malware
- USTC-TFC2016
- Recent encrypted-traffic classification research

### Reconnaissance
- CIC-IDS2017
- UNSW-NB15
- IoTID20 where appropriate

### Exfiltration
- BoT-IoT
- Controlled low-and-slow exfiltration scenarios

### Architecture / operations
- NIST SP 800-82 Rev. 3
- NIST SP 800-94
- NIST Cybersecurity Framework 2.0
- NIST SP 800-61 Rev. 3
- NIST SP 1800-7
- Zeek documentation for connection, DNS, TLS, QUIC, capture loss and operational statistics

---

# 31. Key Source Links

CIC-DDoS2019:
https://www.unb.ca/cic/datasets/ddos-2019.html

CIC-IDS2017:
https://www.unb.ca/cic/datasets/ids-2017.html

CTU / Stratosphere datasets:
https://www.stratosphereips.org/datasets

ExtraHop DGA dataset:
https://github.com/ExtraHop/DGA-Detection-Training-Dataset

DNSTunnel2026:
https://zenodo.org/records/20137065

USTC-TFC2016:
https://github.com/yungshenglu/USTC-TFC2016

UNSW-NB15:
https://research.unsw.edu.au/projects/unsw-nb15-dataset

BoT-IoT:
https://research.unsw.edu.au/projects/bot-iot-dataset

NIST SP 800-82 Rev. 3:
https://csrc.nist.gov/pubs/sp/800/82/r3/final

NIST SP 800-94:
https://csrc.nist.gov/pubs/sp/800/94/final

NIST CSF 2.0:
https://www.nist.gov/cyberframework

NIST SP 800-61 Rev. 3:
https://csrc.nist.gov/pubs/sp/800/61/r3/final

Zeek documentation:
https://docs.zeek.org/

---

# 32. Final Decision

The final model specification should follow this principle:

```text
OBSERVABLE DATA
      ↓
EXACT FEATURE SCHEMA
      ↓
REPRODUCIBLE PREPROCESSING
      ↓
MODEL
      ↓
THREAT SCORE
      ↓
EVIDENCE
      ↓
COMMON PREDICTION
      ↓
BACKEND ALERT
      ↓
RISK / CORRELATION
      ↓
DASHBOARD
```

The final question for every detector is not:

> “Does the model produce a high score?”

It is:

> **“Can we prove that the model was trained on the same observable evidence available at runtime, that its feature schema is exact, that its score has a documented meaning, that it generalizes beyond the training scenario, and that SPECTRA can turn the result into a reproducible evidence-backed alert?”**

That is the standard required for the final SPECTRA SIH implementation.
