# SPECTRA — AI IMPLEMENTATION CONSTITUTION
## Non-Negotiable Rules for All AI Coding / Research Agents

**Status:** FROZEN  
**Applies to:** Claude Code, Cursor, GitHub Copilot, ChatGPT, Gemini, Codex, agents, scripts, or any other AI-assisted development tool used on SPECTRA  
**Purpose:** Prevent an AI agent from silently changing, inventing, weakening, or contradicting the final SPECTRA architecture, ML contracts, security constraints, testing methodology, or SIH claims.

---

# 0. CORE COMMAND

> **DO NOT MAKE ARCHITECTURAL, MODEL, SECURITY, DATA, OR PRODUCT DECISIONS AUTONOMOUSLY.**

The AI is an implementation assistant, not the project architect.

The AI must implement the frozen specification exactly as written.

If the specification does not contain enough information to make a safe implementation decision:

> **STOP. DO NOT GUESS. DO NOT INVENT. DO NOT SUBSTITUTE. REPORT THE GAP AND ASK FOR AN EXPLICIT DECISION.**

A technically “better” idea is still a violation if it changes a frozen requirement without approval.

---

# 1. AUTHORITY ORDER

When instructions conflict, use this order:

```text
1. Explicit current Project Owner decision
2. Frozen SPECTRA Final PRD
3. Frozen SPECTRA ML Detector & Model Integration Specification
4. Approved repository architecture / ownership rules
5. Approved issue/task specification
6. Existing implementation
7. AI preference / general best practice
```

### Absolute rule

General AI knowledge, internet examples, framework conventions, or an AI's preferred architecture **must never override a frozen SPECTRA decision**.

If two frozen documents conflict:

```text
DO NOT CHOOSE ONE SILENTLY.
DO NOT “FIX” IT YOURSELF.
STOP → REPORT THE CONFLICT → REQUEST A DECISION.
```

---

# 2. NO SILENT ARCHITECTURAL CHANGES

The following are frozen:

```text
Passive observation architecture
Zeek-based telemetry
Normalization
Ordering/lateness handling
Detector-specific windowing
Exact feature contracts
Detector adapters
ML inference
Standardized Prediction object
Alert generation
Correlation/Risk layer where implemented
FastAPI REST
WebSocket live delivery
React dashboard
Docker / Docker Compose
Performance/observability layer
PCAP replay path
```

AI must not silently:

- replace FastAPI;
- replace React;
- replace Zeek;
- replace the detector-adapter architecture;
- introduce Kafka;
- introduce Redis;
- introduce Kubernetes;
- split the system into unnecessary microservices;
- introduce a different message broker;
- redesign the entire backend;
- replace the event schema;
- replace the streaming architecture.

Adding infrastructure merely because it sounds more “enterprise” is forbidden unless explicitly approved.

---

# 3. SIX THREAT FAMILIES ARE FROZEN

The product covers exactly these SIH threat families:

```text
1. DDoS
2. C2 Beaconing
3. DGA / DNS Threats
4. Malware in TLS / QUIC encrypted sessions
5. Reconnaissance / Port Scanning
6. Data Exfiltration
```

Internal implementation may contain separate detector modules where required.

Current documented structure:

```text
6 threat families
→ 7 detector modules
```

because DGA and DNS tunnelling are separate detection paths.

The AI must NOT:

- remove a required threat family;
- silently rename a threat family;
- declare a required threat family “optional”;
- count one heuristic as a complete detector;
- claim a detector is complete merely because a model file loads.

---

# 4. PASSIVE-ONLY SECURITY RULE

This is an absolute security boundary.

SPECTRA must operate from passively observable information only.

Allowed:

```text
PCAP
Flow records
Zeek metadata
DNS metadata
TLS metadata
QUIC metadata where genuinely available
timestamps
packet/byte statistics
protocol metadata
connection/flow behavior
```

Forbidden:

```text
Active probes
Active scanning
Sending reconnaissance traffic
Completing a handshake with an observed endpoint
Sending remediation commands
Blocking traffic inline
Modifying production traffic
Using SPECTRA as a network pivot
Decrypting TLS/QUIC payloads
```

### AI must never add code that:

- sends packets back to observed endpoints;
- performs endpoint verification by probing;
- “checks” a suspicious host using an active connection;
- attempts a handshake to obtain information;
- automatically blocks an IP;
- automatically sends a mitigation command.

If a proposed feature requires a return path:

> **REJECT IT.**

---

# 5. SPAN IS NOT A DATA DIODE

The demonstration architecture has this distinction:

```text
SPAN / Mirror
=
passive observation demonstration
```

A physical data diode is:

```text
hardware-enforced one-way communication
```

The AI must never document:

```text
SPAN = data diode
```

The correct statement is:

> “For the prototype, the passive observation boundary is simulated using a switch mirror/SPAN port. Production deployment would use an appropriate passive TAP or hardware-enforced unidirectional gateway/data diode.”

A two-laptop API connection proves:

```text
network connectivity
API reachability
service exposure
```

It does NOT prove:

```text
passive packet capture
SPAN/TAP operation
data-diode behavior
Zeek visibility of another endpoint's traffic
```

Do not merge these claims.

---

# 6. MODEL ↔ BACKEND CONTRACT IS FROZEN

Every detector must have an exact, versioned contract.

Required detector metadata:

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

A model must never receive:

```text
approximate features
placeholder features
invented features
wrongly ordered features
silently missing features
```

The AI must NEVER solve feature mismatch by:

```text
adding random zeroes
dropping arbitrary columns
reordering until it runs
duplicating columns
renaming unrelated columns
padding vectors
truncating vectors
```

unless that behavior is explicitly part of the frozen model specification.

---

# 7. SAME FEATURES DURING TRAINING AND INFERENCE

This rule is absolute:

```text
TRAINING FEATURE SEMANTICS
        =
LIVE INFERENCE FEATURE SEMANTICS
```

Do NOT do:

```text
Train on CICFlowMeter feature set
→
Infer on unrelated Zeek feature set
```

Correct:

```text
Training PCAP
→ Zeek / compatible telemetry
→ SPECTRA feature builder
→ training matrix
→ model

Live passive traffic
→ Zeek
→ SAME SPECTRA feature builder
→ SAME feature schema
→ SAME model
```

If the feature semantics change:

> **Retraining or explicit revalidation is required.**

---

# 8. WINDOW SEMANTICS ARE FROZEN

A logical context window and scoring interval are different concepts.

Example:

```text
Context window = 60 sec
Scoring interval = 1 sec
```

is allowed only if compatible with the model's training semantics.

Do NOT silently change:

```text
5-second tumbling training semantics
```

into:

```text
60-second rolling inference
```

without retraining/revalidation.

The AI must never make window changes merely to “improve latency”.

---

# 9. TEMPORAL DETECTOR RULE

C2, DNS tunnelling, DDoS aggregation, TLS/session behavior, and exfiltration can depend on temporal state.

The AI must preserve:

```text
timestamps
ordering
window semantics
state isolation
lateness policy
```

Do not make C2 a one-flow classifier if its frozen contract requires a sequence.

C2 specifically requires temporal evidence such as:

```text
IAT
periodicity
jitter
destination repetition
burstiness
autocorrelation
```

C2 detection latency must include the time required to collect sufficient observations.

Do not promise instantaneous C2 detection.

---

# 10. EVENT ORDERING IS NOT OPTIONAL

Temporal processing must use a defined lateness policy.

Required architecture:

```text
Incoming events
      ↓
Reorder buffer
      ↓
Timestamp-ordered events
      ↓
Window / detector
```

The AI must preserve configuration for:

```text
maximum lateness
buffer capacity
late-event behavior
quarantine/drop behavior
metrics
```

Do not assume:

```text
arrival order = event timestamp order
```

---

# 11. TIME SEMANTICS ARE FROZEN

Events must distinguish:

```text
observed_at
ingested_at
feature_ready_at
inference_started_at
inference_finished_at
alert_created_at
delivered_at
```

Externally visible timestamps must be UTC-aware.

Use monotonic timers for duration measurements where appropriate.

Do not silently convert timestamps into naive local datetimes.

---

# 12. ML OUTPUT IS NOT THE FINAL ALERT

The model produces a detector prediction.

The backend produces the operational alert.

### Model-level information

```text
status
threat_class
score_type
raw_score
threshold
evidence
context
detector_name/version
model_name/version
feature_schema
```

### Backend-level information

```text
alert_id
incident_id where implemented
asset_id where implemented
observed_at
alert_created_at
delivered_at
flow/event identity
severity
risk score where implemented
lineage
status
```

Do not force model code to own:

```text
WebSocket
FastAPI
dashboard logic
incident assignment
asset criticality
operational severity policy
```

---

# 13. SCORE SEMANTICS MUST NEVER BE LIED ABOUT

Keep these separate:

```text
raw_model_probability
calibrated_confidence
heuristic_score
combined_risk_score
```

A heuristic score is NOT a model probability.

An anomaly score is NOT automatically a probability.

An uncalibrated classifier score must not be advertised as:

```text
“91% probability the attack is real”
```

unless it is actually calibrated and documented.

If calibration is unavailable:

> Prefer the label **Model score** over a misleading probability claim.

---

# 14. SEVERITY MUST NOT BE BASED ONLY ON CONFIDENCE

Do NOT implement:

```text
confidence > 0.90
→ CRITICAL
```

Severity must consider the approved factors:

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

Do not invent a new severity algorithm without approval.

---

# 15. DETECTOR-SPECIFIC NON-NEGOTIABLE RULES

## DDoS

Required coverage:

```text
SYN flood
UDP reflection/amplification-like behavior
spoofed-source flood
```

Evidence should include applicable:

```text
packets/sec
bytes/sec
SYN ratio
source count
source-IP entropy
flow rates
protocol distribution
bidirectional/asymmetry statistics
```

Never classify DDoS only because packet rate is high.

---

## C2

Must preserve:

```text
chronological flows
IAT statistics
periodicity
jitter
destination repetition
burstiness
autocorrelation
```

A C2 model must not silently receive a reduced feature vector.

If the artifact expects 23 features, produce the exact 23-feature schema or repair/retrain under an approved change.

---

## DGA

Must include the required lexical feature family:

```text
domain length
SLD length
entropy
digit ratio
vowel/consonant characteristics
unique-character ratio
dictionary matching
n-grams
```

Required auxiliary artifacts such as:

```text
TF-IDF vectorizer
dictionary
```

must be packaged and versioned.

Never assume the vectorizer is “just a preprocessing detail” that can be omitted.

---

## DNS Tunnelling

Mandatory flow:

```text
DNS events
→ session/query grouping
→ statistical aggregation
→ exact feature vector
→ model
```

No hidden upstream feature builder is allowed.

Evidence must combine, where applicable:

```text
lexical
query length
entropy
query frequency
NXDOMAIN behavior
record-type distribution
request/response sizes
timing/inter-arrival
```

Do not collapse DNS tunnelling into DGA detection.

---

## TLS / QUIC

Two observable paths:

```text
TLS path
QUIC path
```

No payload decryption.

Candidate observable metadata includes:

```text
TLS version
cipher information
extensions
SNI where visible
ALPN
certificate metadata
JA3/JA3S/JA4 where available
packet sizes
timing
session behavior
```

Do not claim:

```text
“Full QUIC malware detection”
```

unless the actual QUIC metadata path and detector have been validated.

Availability of QUIC telemetry is not the same as a validated supervised QUIC-malware classifier.

---

## Recon / Port Scanning

Separate:

```text
model_probability
heuristic_score
```

Potential evidence:

```text
unique destination ports
unique destination hosts
connection count
duration
unanswered/failed connections
fan-out rate
```

Never label a heuristic-derived value as model confidence.

---

## Exfiltration

Exfiltration is REQUIRED.

Never downgrade it to optional.

Required analysis includes:

```text
outbound/inbound byte asymmetry
large outbound transfers
abnormal destinations
flow duration/rate
temporal persistence
```

---

# 16. MODEL DATASET RULES

Every model must document:

```text
dataset
source
license
provenance
attack types
benign population
features
labels
class distribution
PCAP/flow availability
limitations
```

The AI must never silently:

- substitute a different dataset;
- merge incompatible datasets;
- invent labels;
- claim a dataset is representative without evidence;
- claim a model generalizes without an external/independent evaluation.

---

# 17. TRAIN/TEST LEAKAGE IS FORBIDDEN

Do not use naive random row splits when correlated traffic from the same attack campaign can appear in both train and test.

Prefer:

```text
attack/session-aware split
host/source-aware split
time-aware split
dataset-aware validation
```

Where practical:

```text
Train A → Test A
Train A → Test B
Train B → Test A
```

The AI must call out suspected leakage rather than hiding it.

---

# 18. HARD BENIGN TRAFFIC IS REQUIRED

Do not create an artificially easy benchmark where:

```text
attack = strange
benign = boring
```

Include legitimate difficult cases such as:

```text
high-volume traffic
periodic services
modern TLS traffic
DNS-heavy services
cloud/CDN behavior
large legitimate uploads
legitimate scanning/monitoring where relevant
```

The goal is to measure false positives honestly.

---

# 19. NO FAKE RESULTS

The AI must never fabricate:

```text
accuracy
precision
recall
F1
FPR
latency
throughput
packet loss
CPU
RAM
alerts
model confidence
```

If a metric has not been measured:

```text
status = NOT MEASURED
```

not a guessed value.

Do not generate screenshots, reports, charts, or README claims containing invented benchmark numbers.

---

# 20. PACKET RATE ≠ FLOW RATE ≠ TELEMETRY RATE

These are separate quantities:

```text
packets/sec
flows/sec
Mbps
Zeek records/sec
SPECTRA telemetry events/sec
alerts/sec
```

Never substitute one for another.

For example:

```text
500 packet records/sec in a PCAP
```

does NOT prove:

```text
SPECTRA sustains 500 network packets/sec end-to-end
```

---

# 21. LATENCY CLAIMS

Never claim:

```text
“real-time”
“near-real-time”
“sub-10 ms detection”
```

without actual capture-to-alert measurements.

The main metric is:

```text
CAPTURE → ALERT
```

not merely:

```text
MODEL INFERENCE
```

Required latency measurements:

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

Do not use only an average.

---

# 22. CAPTURE LOSS AND APPLICATION DROPS ARE DIFFERENT

Never say:

```text
SPECTRA dropped_events = 0
→ zero packet loss
```

Correct chain:

```text
Network packets
      ↓
Capture loss
      ↓
Zeek records
      ↓
SPECTRA received
      ↓
SPECTRA processed
      ↓
Alerts
```

The AI must report these separately:

```text
capture loss
unsupported records
malformed records
SPECTRA queue drops
detector failures
```

---

# 23. QUEUE / BACKPRESSURE RULES

Queues must remain bounded.

The AI must not “solve” overload by silently:

```text
making queues infinite
removing queue limits
allocating unbounded memory
disabling backpressure
blocking the entire system indefinitely
```

On overflow, the approved system must expose controlled behavior and metrics.

If a drop policy changes, document:

```text
what is dropped
when it is dropped
why
how it is measured
```

---

# 24. REPLAY SEMANTICS

PCAP replay is a testing mechanism, not proof of live network throughput.

Clearly distinguish:

```text
FAST replay
FIXED-RATE replay
TIMESTAMP-PRESERVING replay
```

Only use a replay mode that matches the metric being measured.

Do not compare:

```text
fast replay speed
```

with:

```text
live network throughput
```

as if they were the same.

---

# 25. LIVE MODE / REPLAY MODE / TEST MODE

The system must preserve a clear distinction.

### LIVE

```text
real passive telemetry
no mock detector
no synthetic alert injection
no automatic replay
```

### REPLAY

```text
prepared PCAP / Zeek telemetry
known scenario
known ground truth
reproducible evaluation
```

### TEST

```text
controlled unit/integration behavior
mocking allowed only where explicitly required
```

Do not allow test/mocked behavior to silently leak into the live demonstration.

---

# 26. NO PLACEHOLDER FEATURES IN PRODUCTION DETECTORS

This is forbidden:

```python
return {
    "feature_a": 0,
    "feature_b": 0,
    ...
}
```

just to make a model execute.

If the true feature calculation is unavailable:

```text
STOP
REPORT MISSING FEATURE
DO NOT FAKE IT
```

The only exception is when the model contract explicitly defines a legitimate default value for that field.

---

# 27. NO SILENT COMPATIBILITY HACKS

When a serialized model fails:

```text
XGBoost version mismatch
scikit-learn mismatch
corrupt artifact
missing vectorizer
missing dictionary
missing scaler
```

the AI must NOT:

- change random dependencies until it works;
- downgrade/upgrade packages without documenting the compatibility decision;
- retrain a replacement model without approval;
- modify a model artifact silently;
- change feature order until prediction succeeds.

Correct sequence:

```text
identify failure
→ record exact error
→ identify required compatibility
→ request/implement approved repair
→ rerun validation
```

---

# 28. MODEL ARTIFACTS ARE TRUSTED AS CONTROLLED ASSETS

Required artifacts must be packaged with:

```text
model
preprocessor
feature schema
config
threshold
model card
checksum
```

Where applicable:

```text
vectorizer
dictionary
baseline model/state
```

The AI must verify artifacts at startup.

Missing or incompatible artifacts should produce a controlled startup failure, not a fake fallback.

---

# 29. DO NOT MODIFY OWNED MODEL SOURCES WITHOUT APPROVAL

Where repository ownership has been assigned:

```text
P1/P2 detector implementations
training notebooks
serialized model artifacts
handover documents
detector-specific tests
```

must not be modified by an integration agent unless the owning team explicitly approves the change.

P3-owned work is:

```text
adapters
feature preparation
registry wiring
schemas
orchestration
integration
APIs
deployment
system tests
```

If ownership is ambiguous:

> STOP AND ASK.

---

# 30. NO SILENT MOCKING

A mock detector must never be introduced to make the system “look like it works”.

The AI must not:

```text
replace model failure with fake detections
generate synthetic alerts in LIVE mode
return hard-coded “healthy” responses
fake confidence values
fake throughput
fake latency
```

A missing detector should be reported as:

```text
NOT READY / ERROR
```

not disguised as success.

---

# 31. ALERT STORM PROTECTION

Do not emit unlimited duplicate alerts for the same underlying behavior.

Where alert aggregation/deduplication is implemented, preserve:

```text
deduplication key
suppression window
cooldown
observation count
supporting evidence
```

Do not throw away evidence simply to reduce alert volume.

---

# 32. EVIDENCE MUST BE TRACEABLE

Every alert should be traceable:

```text
Observed traffic
      ↓
source log
      ↓
event ID
      ↓
feature snapshot
      ↓
model/version
      ↓
prediction
      ↓
alert
```

Recommended lineage:

```text
source log
source record reference
observed timestamp
ingestion timestamp
processing timestamp
model version
feature-schema version
evidence hash
```

The AI must never invent evidence after the fact.

---

# 33. NO INVENTED MITRE ATT&CK MAPPINGS

ATT&CK mapping is allowed only where the evidence supports it.

Do NOT add ATT&CK IDs merely to make the dashboard look professional.

If there is insufficient evidence:

```text
mapping = UNSPECIFIED
```

rather than inventing a technique.

---

# 34. DO NOT CLAIM NIST COMPLIANCE

The project is:

```text
architecturally informed by NIST
```

not:

```text
NIST certified
NIST compliant
NIST validated
```

unless an authorized project owner explicitly establishes such a claim through a separate compliance process.

---

# 35. NETWORK PROTOCOL SCHEMA MUST NOT BE OVER-FORCED

Do not make every telemetry record require:

```text
TCP
UDP
ICMP
source port
destination port
```

when DNS/TLS/QUIC records may not naturally contain the same fields.

Protocol-specific data belongs in the appropriate raw/typed extension.

Do not fabricate fields solely to satisfy a rigid schema.

---

# 36. FAILURE HANDLING IS PART OF THE PRODUCT

The AI must test and preserve behavior for:

```text
Zeek unavailable
model unavailable
model incompatible
malformed event
unsupported log
queue full
slow WebSocket client
backend restart
out-of-order event
missing artifact
missing feature
high traffic
```

A detector failure must not silently terminate the entire system.

A malformed event must not silently crash the runtime.

A full queue must produce controlled metrics.

---

# 37. RESTART BEHAVIOR MUST BE EXPLICIT

Do not silently assume that state survives restart.

Stateful detectors may maintain:

```text
C2 temporal history
DNS aggregation
TLS baseline
window state
```

If restart loses state:

```text
document it
measure it
recover it if the approved architecture requires recovery
```

Do not silently invent persistence.

---

# 38. NO SECURITY-WEAKENING CHANGES

Never disable or weaken:

```text
validation
checksums
model compatibility checks
input validation
queue bounds
failure isolation
read-only constraints
tests
security controls
```

merely to make a demo pass.

Forbidden examples:

```text
disable validation
catch all exceptions and pretend success
always return HTTP 200
ignore model-loading failures
set verification=False
remove bounds because “it improves throughput”
```

---

# 39. NO DESTRUCTIVE COMMANDS WITHOUT EXPLICIT APPROVAL

AI agents must not casually execute:

```text
git reset --hard
git clean -fd
delete large model files
overwrite model artifacts
rewrite Git history
force-push
remove project files
delete datasets
```

If a destructive operation appears necessary:

```text
STOP
explain exactly what will be deleted/changed
request approval
```

---

# 40. GIT RULES

Before changes:

```text
git status
git branch
git log -n appropriate amount
```

After changes:

```text
git diff
git status
tests
```

Do not:

```text
force-push
rewrite history
change remotes
change branches
```

without explicit instruction.

Never silently push code to a different repository or remote.

---

# 41. TEST RULE

After any meaningful implementation change:

```text
run the narrow relevant test
→ run affected integration tests
→ run broader test suite
→ inspect failures
```

Never:

```text
delete tests
disable tests
skip failing tests
change assertions only to make them pass
```

unless the test itself is objectively incorrect and the change is explicitly approved.

---

# 42. “MAKE IT WORK” DOES NOT OVERRIDE THE SPEC

If an AI encounters:

```text
model won't load
feature missing
window incompatible
latency target missed
throughput too low
live capture unavailable
```

the correct behavior is NOT:

```text
invent a workaround
```

The correct behavior is:

```text
identify root cause
→ preserve frozen constraints
→ propose the smallest compliant fix
→ stop at unresolved decisions
```

---

# 43. NO UNAPPROVED NEW DEPENDENCIES

Do not add a new package merely because:

```text
“it is easier”
“everyone uses it”
“the AI prefers it”
```

Before adding a dependency:

```text
Why is it required?
Does the frozen architecture require it?
Can existing dependencies satisfy the requirement?
Does it affect deployment?
Does it affect security?
Does it affect reproducibility?
```

If the answer requires an architectural decision:

> STOP AND ASK.

---

# 44. NO RANDOM RETRAINING

An AI must never retrain a detector simply because:

```text
the old model does not fit
the old model is inconvenient
the current feature schema is difficult
the AI found a different dataset
```

Retraining requires an explicit, documented decision covering:

```text
dataset
feature schema
preprocessing
window semantics
model
threshold
evaluation
artifact version
deployment contract
```

---

# 45. NO DATASET SUBSTITUTION

Do not silently replace the approved training/validation data.

If a dataset becomes unavailable, unsuitable, incompatible, or legally unusable:

```text
STOP
REPORT THE PROBLEM
PROPOSE OPTIONS
WAIT FOR APPROVAL
```

---

# 46. NO OVERCLAIMING

The AI must preserve the distinction between:

```text
implemented
tested
validated
benchmarked
planned
architected
```

For example:

### Correct

```text
“QUIC telemetry path implemented; supervised QUIC-malware validation pending.”
```

### Forbidden

```text
“Full QUIC malware detection implemented”
```

when it has not been validated.

Similarly:

```text
“0 SPECTRA event drops”
```

does not become:

```text
“0 packet loss”
```

and:

```text
“12 ms inference”
```

does not become:

```text
“12 ms end-to-end detection”
```

---

# 47. REQUIRED PERFORMANCE TERMS

Use these exact meanings:

```text
Inference latency
=
model invocation duration

Processing latency
=
runtime processing duration

Detection latency
=
observation/evidence acquisition
+
processing until detection

Capture-to-alert latency
=
observed_at → alert_created_at

Capture-to-dashboard latency
=
observed_at → delivered_at
```

Do not mix these terms.

---

# 48. DEMONSTRATION RULES

The final demonstration uses:

```text
Minimum practical live topology:

Laptop A = SPECTRA
Laptop B = controlled traffic source
Laptop C = simulated target
Managed Ethernet switch = SPAN/mirror
```

Optional:

```text
B1/B2/B3 = multiple controlled sources
```

The threat source must send traffic to the simulated target.

SPECTRA should receive a passive copy.

Do not make the demo:

```text
Threat laptop → FastAPI website
```

and call that passive network detection.

That proves API reachability, not passive monitoring.

---

# 49. LIVE DEMO SAFETY

Allowed:

```text
controlled synthetic traffic
authorized lab endpoints
prepared PCAPs
safe test programs
```

Forbidden:

```text
real malware on campus networks
attacking public infrastructure
uncontrolled DDoS
uncontrolled scanning
unauthorized packet injection
real credential theft
real data exfiltration
```

For scenarios such as spoofing, reflection, distributed DDoS, or malware-like encrypted traffic:

> Prefer prepared PCAPs and controlled fixtures.

---

# 50. PCAP FALLBACK IS MANDATORY

Never depend on live traffic alone.

Fallback order:

```text
PRIMARY:
Live passive traffic
→ Zeek
→ SPECTRA
→ dashboard

SECONDARY:
Prepared PCAP
→ Zeek
→ SPECTRA
→ dashboard

EMERGENCY:
Pre-recorded evidence/demo dataset
```

The fallback should use the same alert schema and UI wherever possible.

---

# 51. AI MUST INSPECT BEFORE EDITING

Before modifying code:

```text
1. Read repository structure.
2. Identify ownership.
3. Read relevant existing implementation.
4. Read tests.
5. Read configuration.
6. Identify current behavior.
7. Compare against frozen specification.
8. Make the smallest compliant change.
```

Do not rewrite files blindly.

Do not replace working implementations merely because another implementation is prettier.

---

# 52. AI MUST PRESERVE WORKING BEHAVIOR

Before a change, identify:

```text
what already works
```

After the change, verify:

```text
previous behavior still works
```

A new feature that breaks:

```text
Zeek ingestion
REST
WebSocket
PCAP replay
existing detectors
```

is not a successful implementation.

---

# 53. NO “CLEAN REWRITE” WITHOUT AUTHORIZATION

The phrase:

> “I rewrote the backend because the existing structure was messy.”

is NOT acceptable.

A full rewrite is a major architectural decision.

The default rule is:

```text
PATCH / EXTEND
instead of
REWRITE
```

unless explicitly approved.

---

# 54. WHEN AN AI HAS A BETTER IDEA

The AI may identify:

```text
performance improvement
security improvement
architecture alternative
new model
new dataset
new framework
new dashboard
```

It must NOT silently implement it.

Instead:

```text
CURRENT FROZEN DECISION
+
PROPOSED CHANGE
+
WHY
+
IMPACT
+
WHAT REQUIREMENTS CHANGE
```

Then wait for approval.

---

# 55. CHANGE CONTROL

Any change to a frozen requirement must be treated as a formal change.

Required record:

```text
CHANGE ID:
CURRENT REQUIREMENT:
PROPOSED CHANGE:
REASON:
IMPACT:
AFFECTED COMPONENTS:
AFFECTED TESTS:
AFFECTED DATA/MODELS:
SECURITY IMPACT:
PERFORMANCE IMPACT:
APPROVED BY:
DATE:
```

No implementation until the change is approved.

---

# 56. RELEASE GATES ARE NOT OPTIONAL

The SIH release candidate requires:

```text
1. Functional
2. Model
3. Streaming
4. Latency
5. Throughput
6. Loss
7. Quality
8. Passive boundary
9. Evidence
10. Demo
```

A detector is not “done” because it imports.

A model is not “done” because it loads.

A system is not “real time” because inference is fast.

A network is not “one-way” because the architecture diagram says so.

A benchmark is not valid because a PCAP was generated at that rate.

---

# 57. MANDATORY “STOP CONDITIONS”

The AI MUST STOP and request a decision when:

```text
[ ] Two specifications conflict.
[ ] A required feature is undefined.
[ ] A model expects an unknown schema.
[ ] A model artifact is missing.
[ ] A dataset needs substitution.
[ ] A window must change to make the detector work.
[ ] A new dependency changes the architecture.
[ ] A security boundary must be weakened.
[ ] A test must be disabled to pass.
[ ] A production claim cannot be proven.
[ ] A packet/flow/event metric is ambiguous.
[ ] Live passive capture cannot be implemented with the current hardware.
[ ] A detector's ownership is unclear.
[ ] A destructive Git operation appears necessary.
[ ] The AI would otherwise need to invent a value.
```

---

# 58. MANDATORY “DO NOT LIE” RULE

If the AI does not know:

```text
say unknown
```

If the AI has not measured:

```text
say not measured
```

If the AI has not validated:

```text
say not validated
```

If the AI cannot prove:

```text
do not claim
```

Never replace uncertainty with confidence.

---

# 59. FINAL FROZEN ARCHITECTURE

The intended final architecture is:

```text
                 CRITICAL / TEST NETWORK
                         │
                    TRAFFIC COPY
                         │
                         ▼
              PASSIVE TAP / SPAN /
              UNIDIRECTIONAL BOUNDARY
                         │
                         ▼
                       ZEEK
                         │
           ┌─────────────┴──────────────┐
           │                            │
       TELEMETRY                  CAPTURE HEALTH
           │                            │
           ▼                            ▼
      VALIDATION                 CAPTURE LOSS
           │
           ▼
      NORMALIZATION
           │
           ▼
     ORDERING/LATENESS
           │
           ▼
      WINDOW MANAGER
           │
           ▼
     FEATURE ENGINE
           │
     ┌─────┼───────────────────────────────┐
     ▼     ▼      ▼       ▼      ▼        ▼
    DDoS   C2     DGA     DNS    TLS     Recon
                                      │
                                    QUIC
     └─────┴──────┴───────┴──────┴───────┘
                     │
                  Exfiltration
                     │
                     ▼
             COMMON PREDICTION
                     │
                     ▼
             EVIDENCE ENGINE
                     │
                     ▼
              CORRELATION/RISK
                     │
                     ▼
                ALERT ENGINE
                     │
             ┌───────┴────────┐
             ▼                ▼
         REST API         WebSocket
             │                │
             └───────┬────────┘
                     ▼
                REACT SOC UI

      PERFORMANCE / OBSERVABILITY
      ────────────────────────────
      throughput
      capture loss
      event drops
      queue depth
      CPU
      RAM
      P50/P95/P99 latency
      detector failures
```

---

# 60. FINAL PRODUCT CLAIM

The frozen product claim is:

> **SPECTRA is a passive AI-assisted network threat intelligence platform for critical infrastructure. It receives only a one-way copy of network activity, uses Zeek to generate structured telemetry, processes that telemetry incrementally through detector-specific feature pipelines, evaluates DDoS, C2, DGA/DNS tunnelling, encrypted TLS/QUIC traffic, reconnaissance and exfiltration, produces evidence-backed standardized alerts, and exposes them through FastAPI/WebSockets to an analyst dashboard. Its near-real-time claim is valid only to the extent supported by measured capture-to-alert latency, throughput, loss, resource and detector-validation results.**

---

# 61. FINAL DEVELOPMENT LOOP

Every implementation task must follow:

```text
READ
 ↓
UNDERSTAND
 ↓
COMPARE WITH FROZEN SPEC
 ↓
IDENTIFY MINIMAL CHANGE
 ↓
IMPLEMENT
 ↓
TEST
 ↓
MEASURE
 ↓
VERIFY NO FROZEN RULE WAS BROKEN
 ↓
REPORT EXACTLY WHAT CHANGED
```

Never:

```text
GUESS
 ↓
CHANGE ARCHITECTURE
 ↓
HIDE THE CHANGE
```

---

# 62. FINAL COMMANDMENT

> **The AI is allowed to optimize implementation.**
>
> **The AI is NOT allowed to optimize the requirements.**

Requirements are frozen unless explicitly changed by the project owner.

When in doubt:

```text
STOP.
DO NOT INVENT.
DO NOT WEAKEN.
DO NOT SUBSTITUTE.
ASK.
```

That rule overrides every AI preference.

---

# 63. PRE-COMMIT AI SELF-CHECK

Before declaring any task complete, the AI must answer YES to all applicable questions:

```text
[ ] Did I preserve the passive/read-only architecture?
[ ] Did I avoid all return-path/probing behavior?
[ ] Did I avoid payload decryption?
[ ] Did I preserve the frozen threat coverage?
[ ] Did I preserve exact feature contracts?
[ ] Did I avoid placeholder features?
[ ] Did I preserve training/inference feature semantics?
[ ] Did I preserve temporal/window semantics?
[ ] Did I preserve timestamp/ordering semantics?
[ ] Did I preserve score semantics?
[ ] Did I avoid fabricated metrics?
[ ] Did I distinguish packets/flows/events?
[ ] Did I distinguish inference latency from detection latency?
[ ] Did I distinguish capture loss from application drops?
[ ] Did I avoid fake/mocked live alerts?
[ ] Did I avoid unapproved dependencies?
[ ] Did I avoid destructive Git operations?
[ ] Did I run the appropriate tests?
[ ] Did I preserve previously working behavior?
[ ] Did I document unresolved limitations?
[ ] Did I avoid overclaiming?
[ ] Did I make no unapproved architectural decision?
```

If any applicable answer is **NO**:

> **THE TASK IS NOT COMPLETE.**

---

# 64. FINAL STATUS

This file is the **AI guardrail document** for the SPECTRA implementation.

It does not replace the PRD or the ML specification.

It exists to prevent an AI coding/research agent from making autonomous decisions that could invalidate the frozen project architecture, ML contracts, security constraints, experimental results, or SIH claims.
