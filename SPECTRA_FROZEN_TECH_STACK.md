# SPECTRA — FROZEN TECHNOLOGY STACK
## Non-Negotiable Stack for Final Implementation

**Status:** FROZEN / IMPLEMENTATION BASELINE  
**Purpose:** Prevent AI agents or developers from silently replacing, adding, or removing core technologies without an explicit project-owner decision.

---

# 1. Core Principle

The technology stack is part of the frozen architecture.

AI agents must not replace a technology simply because another tool is:

- newer,
- easier,
- more popular,
- more performant in a generic benchmark,
- preferred by the AI,
- easier to code.

Any stack change requires an explicit architecture/change-control decision.

---

# 2. Frozen Final Stack

## A. Network Telemetry / Observation

### Zeek

**Role:**
- passive network monitoring;
- protocol analysis;
- network metadata generation;
- connection/DNS/TLS/QUIC-related telemetry;
- capture/operational statistics.

**Required position:**

```text
Passive traffic
      ↓
Zeek
      ↓
Structured telemetry
```

Zeek is the primary telemetry source for the SPECTRA prototype.

### Important rule

Do not replace Zeek with another network-monitoring system without explicit approval.

Additional telemetry sources such as NetFlow/IPFIX/sFlow are a future extension, not a silent replacement for the Zeek path.

---

# 3. Backend Language

## Python

Python is the frozen backend and ML integration language.

Use Python for:

- telemetry ingestion;
- normalization;
- ordering;
- windowing;
- feature extraction;
- model inference;
- detector adapters;
- alert generation;
- metrics;
- backend services.

Do not introduce a second backend language merely to implement existing SPECTRA functionality.

---

# 4. Backend API Framework

## FastAPI

FastAPI is the frozen backend API framework.

Use it for:

```text
REST API
WebSocket API
health/readiness
statistics
alerts
backend service
```

Required REST interfaces include:

```text
GET /health
GET /stats
GET /alerts
GET /alerts/{id}
```

Required WebSocket:

```text
/ws
```

Do not replace FastAPI with Flask, Django, Node.js/Express, Spring Boot, or another framework without explicit approval.

---

# 5. ASGI Server

## Uvicorn

Uvicorn is the default server for FastAPI development and deployment.

Required development pattern:

```text
FastAPI
   ↓
Uvicorn
```

Do not silently replace Uvicorn with another server because a generic benchmark says it is faster.

Production deployment may use another ASGI process manager only if explicitly approved.

---

# 6. Backend Data Validation

## Pydantic

Pydantic is the schema/validation layer for API and internal structured data where appropriate.

Use it for:

- request/response schemas;
- alert contracts;
- configuration validation;
- typed backend structures.

Do not remove validation simply to make malformed data pass.

---

# 7. ML / Data Science Stack

## scikit-learn

Use scikit-learn for:

- preprocessing;
- scalers;
- evaluation;
- baseline models;
- metrics;
- calibration where selected;
- compatible ML utilities.

## XGBoost

Primary supervised tree-model family for appropriate structured network-feature problems.

Recommended for:

- DDoS;
- C2;
- DGA;
- DNS tunnelling;
- TLS where appropriate;
- reconnaissance;
- exfiltration.

## LightGBM

Allowed approved alternative for tree-based structured models when benchmark evidence justifies it.

It must not be introduced merely because it is fashionable.

## NumPy

Use for numerical arrays and feature processing.

## Pandas

Use for tabular data preparation, dataset processing, analysis and evaluation.

## SciPy

Use where required for numerical/statistical processing.

## Joblib

Use where required for compatible scikit-learn model/preprocessor serialization.

---

# 8. ML Model Selection Rule

The stack does NOT mean every detector must use the same algorithm.

The approved model families are:

```text
Logistic Regression
Random Forest
XGBoost
LightGBM
Isolation Forest where appropriate
```

Selection must be based on:

```text
F1
Recall
False Positive Rate
Generalization
Latency
Model size
Feature compatibility
```

Do not select a deep neural network merely to make the project sound more advanced.

---

# 9. Deep Learning Rule

PyTorch/TensorFlow are NOT part of the default frozen MVP stack.

They may be introduced only after an explicit model-design decision proves that a detector requires them.

The default rule is:

```text
Tabular/network features
        ↓
Classical ML
```

Do not add GPU infrastructure unless the project owner explicitly approves it.

---

# 10. Frontend

## React

React is the frozen frontend framework.

Use it for:

- SOC dashboard;
- live alerts;
- system health;
- threat summaries;
- evidence visualization;
- performance metrics;
- incident views where implemented.

Do not replace React with Angular, Vue, Svelte, Next.js, or another frontend framework without explicit approval.

---

# 11. Frontend Development Tooling

## Vite

Vite is the preferred frontend development/build tool for the React dashboard if already used by the repository.

Do not introduce a second frontend build system.

The final frontend architecture should remain:

```text
React
  ↓
Vite
  ↓
Browser
```

---

# 12. Real-Time Communication

## WebSocket

WebSocket is the frozen real-time communication mechanism between:

```text
FastAPI backend
        ↕
React dashboard
```

Use it for:

- new alerts;
- live status;
- approved real-time dashboard events.

Do not implement “real time” by polling `/alerts` every second.

REST remains for request/response operations.

---

# 13. Network Test / Replay Data

## PCAP

PCAP is the frozen reproducibility mechanism.

Use PCAP for:

- detector validation;
- regression testing;
- stress testing;
- SIH fallback demonstration;
- controlled malicious-behavior simulation.

PCAP replay must pass through the same downstream processing path as practical:

```text
PCAP
 ↓
Zeek
 ↓
SPECTRA
```

Do not use fabricated JSON alerts as a replacement for the replay pipeline.

---

# 14. Live Capture Architecture

The live sensor should use:

```text
Passive TAP / SPAN / appropriate one-way boundary
          ↓
Capture-capable network interface
          ↓
Zeek
          ↓
SPECTRA
```

### Reference platform rule

For the final live sensor, Linux should be the preferred reference environment for Zeek-based capture.

Windows may remain a development environment, but the team must not assume that a Windows development setup is equivalent to a production sensor.

Do not describe a SPAN port as a physical data diode.

---

# 15. Containerization

## Docker

Docker is the frozen containerization technology.

Use it for:

- backend packaging;
- reproducible runtime;
- isolation;
- controlled deployment.

## Docker Compose

Docker Compose is the frozen orchestration method for the SIH prototype.

Use it to start the required services without introducing Kubernetes.

---

# 16. Kubernetes Rule

Kubernetes is NOT part of the SPECTRA SIH MVP stack.

Do not add:

```text
Kubernetes
Helm
service mesh
cluster autoscaling
```

unless the project scope explicitly changes.

The current problem does not require that infrastructure.

---

# 17. Message Broker Rule

The default architecture does NOT require:

```text
Kafka
RabbitMQ
NATS
Redis Streams
```

The existing in-process streaming runtime and bounded queues remain the default MVP implementation.

A message broker may only be added after an explicit architecture decision backed by a measured requirement.

---

# 18. Database / Persistence Rule

The architecture requires a persistent evidence/alert strategy, but the exact database technology is intentionally **not to be changed by an AI agent silently**.

Before implementing a persistent store, the project owner must explicitly freeze one of:

```text
SQLite
PostgreSQL
another approved store
```

Until that decision is made:

- do not introduce a database merely because it is convenient;
- do not silently add PostgreSQL;
- do not silently add MongoDB;
- do not silently add Redis as a database.

The storage technology is a controlled architecture decision.

---

# 19. Observability

The core runtime must expose application-level observability.

Required measurements:

```text
events_received
events_processed
events_dropped
events_quarantined
late_events
detector_failures
queue_depth
queue_peak
input_rate
processing_rate
capture_loss
latency_p50
latency_p95
latency_p99
CPU
RAM
alerts_total
alerts_by_detector
```

The implementation may begin with application metrics/logging already present in the backend.

A full Prometheus/Grafana stack is NOT required for the SIH MVP unless explicitly approved.

---

# 20. Logging

Use structured application logs where practical.

Logs should make it possible to determine:

```text
what happened
when
where
which detector
which model
which event
which error
```

Do not log secrets, credentials, or sensitive payload data.

---

# 21. Configuration

Use controlled configuration for:

```text
detector enable/disable state
model paths
thresholds
window durations
scoring cadence
queue sizes
lateness bounds
capture configuration
environment mode
```

Recommended environment modes:

```text
LIVE
REPLAY
TEST
```

Do not hardcode environment-specific settings deep inside detector code.

---

# 22. Dependency Versioning

The final runtime must pin compatible versions for the critical stack.

At minimum track:

```text
Python
NumPy
Pandas
SciPy
scikit-learn
XGBoost
LightGBM if used
joblib
FastAPI
Uvicorn
Pydantic
React
Vite
Zeek
Docker
```

Exact versions must come from the final compatibility audit.

AI agents must not randomly upgrade/downgrade dependencies to solve a model-loading or runtime problem.

---

# 23. Model Artifact Technology

Supported model artifact types depend on the selected framework.

Examples:

```text
XGBoost model
scikit-learn/joblib artifact
LightGBM model
```

Each deployed model must include:

```text
model
preprocessor
feature schema
threshold
model version
model card
checksum
```

For DGA where required:

```text
vectorizer
dictionary
```

For detectors with additional state:

```text
approved baseline/state artifact
```

Do not ship an artifact without its required preprocessing dependencies.

---

# 24. Source Control

## Git

Git is mandatory for source control.

## GitHub

GitHub is the project collaboration/repository platform.

Do not silently change repository/remotes.

Do not force-push or rewrite history without explicit authorization.

---

# 25. CI/CD

A lightweight GitHub Actions pipeline is recommended for:

```text
tests
schema checks
model-artifact checks
Docker build
basic replay regression
```

It is NOT necessary to add a complex deployment platform.

---

# 26. Security Stack Rule

Do not add a security product simply because it sounds enterprise-grade.

The following are not automatically required:

```text
SIEM
SOAR
EDR
WAF
IDS vendor appliance
Kubernetes security platforms
enterprise service mesh
```

SPECTRA's purpose is the passive detection/intelligence layer.

External security products may be integrated later.

---

# 27. Frozen End-to-End Stack

The final core stack is:

```text
NETWORK
  Passive TAP / SPAN / One-way Boundary
             ↓
          Zeek
             ↓
PYTHON
  Ingestion
  Validation
  Normalization
  Reordering
  Windowing
  Feature Engineering
             ↓
ML
  scikit-learn
  XGBoost
  LightGBM where justified
             ↓
BACKEND
  FastAPI
  Uvicorn
  Pydantic
  WebSocket
             ↓
OBSERVABILITY
  application metrics/logging
             ↓
FRONTEND
  React
  Vite
             ↓
DEPLOYMENT
  Docker
  Docker Compose
             ↓
VERSION CONTROL
  Git
  GitHub
```

---

# 28. Technologies That AI Must Not Add Without Approval

The following require an explicit architecture decision:

```text
Kafka
Redis
RabbitMQ
NATS
Kubernetes
Helm
PostgreSQL
MongoDB
Prometheus
Grafana
PyTorch
TensorFlow
additional backend languages
additional frontend frameworks
additional message buses
service mesh
GPU infrastructure
cloud-specific managed services
```

This does not mean these technologies are inherently bad.

It means:

> **They are not part of the frozen SPECTRA MVP unless explicitly approved.**

---

# 29. Technologies That AI Must Not Remove

Do not silently remove:

```text
Zeek
Python
FastAPI
WebSocket
React
Docker / Docker Compose
PCAP replay
scikit-learn/XGBoost/approved tree-model stack
bounded queues
application metrics
```

unless the project owner approves the architectural change.

---

# 30. Tech-Stack Change Control

Any proposed technology replacement must document:

```text
CURRENT TECHNOLOGY:
PROPOSED TECHNOLOGY:
WHY:
PERFORMANCE IMPACT:
SECURITY IMPACT:
DEPLOYMENT IMPACT:
TEST IMPACT:
MODEL IMPACT:
LATENCY IMPACT:
THROUGHPUT IMPACT:
NEW DEPENDENCIES:
REMOVAL OF OLD DEPENDENCY:
```

No implementation begins until the change is approved.

---

# 31. Final Rule

The AI must never think:

> “This project would be better with another technology.”

The correct question is:

> **“Does the frozen SPECTRA specification require this technology change?”**

If not:

```text
KEEP THE FROZEN STACK.
```

The stack is frozen for the final implementation unless the project owner explicitly changes it.
