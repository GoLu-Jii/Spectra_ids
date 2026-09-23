# SPECTRA PortScan Detector

## 1. Overview

The PortScan detector is a binary supervised classifier used by SPECTRA to
distinguish:

```text
0 → Benign
1 → PortScan
```

### Current model

```text
Model: XGBoost
Model type: XGBClassifier
Feature schema: v1.0
Feature count: 8
Decision threshold: 0.50166595
```

The detector operates on flow-level network telemetry and returns a binary
PortScan decision together with the model score and feature evidence.

---

## 2. Model Artifact

### Artifact

```text
spectra_portscan_detector.joblib
```

The current notebook model is `model_ps2`.

The artifact is the trained XGBoost model saved with `joblib`.

### XGBoost configuration

```text
n_estimators  = 300
max_depth     = 6
learning_rate = 0.1
random_state  = 42
eval_metric   = logloss
```

### Score and threshold

The detector uses the positive-class output from:

```python
model.predict_proba(X)[:, 1]
```

The model-native decision boundary reproduced from the trained
`model_ps2.predict()` behavior is:

```text
raw_score >= 0.50166595 → PortScan
raw_score <  0.50166595 → Benign
```

This value was obtained by checking the trained model's test-set probabilities
and finding the threshold that exactly reproduces `model_ps2.predict()`.

It is **not a validation-tuned threshold**. Do not change it independently of
the model without rechecking the model's predictions.

The score should be treated as a **model score**, not as a calibrated
probability.

---

## 3. Feature Contract

The model expects exactly these 8 features in this order:

```text
1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Backward Packets
5. Flow Packets/s
6. Fwd Packets/s
7. Bwd Packets/s
8. FIN Flag Count
```

The authoritative schema is:

```text
spectra_portscan_feature_schema.json
```

### Required runtime fields

The SPECTRA telemetry/feature layer must provide these exact CIC-style fields:

```text
Destination Port
Flow Duration
Total Fwd Packets
Total Backward Packets
Flow Packets/s
Fwd Packets/s
Bwd Packets/s
FIN Flag Count
```

### Feature engineering

There is **no additional feature engineering** in the final model.

The eight runtime fields are passed directly to XGBoost in the frozen order
above.

Before inference:

```text
infinity values → NaN
NaN values      → 0
```

Numeric fields must be convertible to numeric values.

Training and runtime must use the same feature names, order, units, and
semantics.

---

## 4. Inference Pipeline

```text
Passive network telemetry
        ↓
SPECTRA upstream telemetry/feature adapter
        ↓
Required flow fields
        ↓
8-feature vector
        ↓
XGBoost model
        ↓
raw model score
        ↓
threshold = 0.50166595
        ↓
Benign / PortScan
        ↓
standardized detector result
```

The detector does not perform packet capture or telemetry generation.

Those responsibilities remain with the upstream SPECTRA pipeline.

---

## 5. Runtime Integration

### Runtime module

```text
portscan_detector.py
```

The module is responsible for:

- loading the model artifact
- loading and validating the feature schema
- validating required runtime fields
- constructing the exact 8-feature vector
- running inference
- applying the frozen decision threshold
- returning the standardized detector result

It does not contain training or dataset code.

### Required runtime files

```text
detectors/portscan/
├── portscan_detector.py
├── spectra_portscan_detector.joblib
├── spectra_portscan_feature_schema.json
└── port_scan_model.md
```

### Integration

Single-flow inference:

```python
result = detector.predict_flow(flow)
```

Batch inference:

```python
results = detector.predict_batch(flow_dataframe)
```

The `flow` object must contain all eight required runtime fields.

---

## 6. Detector Output

The detector result should provide the fields required by the SPECTRA
backend:

```text
status
threat_class
score_type
raw_score
threshold
evidence
context
detector_name
detector_version
model_name
model_version
feature_schema
```

For this detector:

```text
threat_class = "PortScan"
score_type   = "model_score"
```

Example decision:

```text
status       = "DETECTED"
threat_class = "PortScan"
raw_score    = <model score>
threshold    = 0.50166595
```

The eight feature values used for the decision should be returned as
`evidence` so the backend/dashboard can display what the model saw.

Severity, alert aggregation, correlation, and overall risk scoring remain
backend responsibilities.

---

## 7. Model Training and Validation

### Dataset

```text
CIC-IDS2017
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

Dataset size used in the notebook:

```text
286,467 rows
79 original columns
```

Labels:

```text
BENIGN   = 127,537
PortScan = 158,930
```

The notebook performs the final binary label mapping:

```text
BENIGN   → 0
PortScan → 1
```

### Data preparation

The notebook:

1. strips whitespace from column names
2. removes unused/redundant columns
3. removes a constant column
4. removes selected highly correlated features
5. replaces infinite values with NaN
6. fills NaN values with 0
7. creates the final 8-feature matrix

The final model does not require the complete 79-column dataset at runtime.

### Train/test split

The final evaluation uses an 80/20 stratified split with:

```text
random_state = 42
```

Test set:

```text
57,300 rows
```

The final model is `model_ps2`.

### Current test results

```text
Accuracy:  0.9808028

              precision    recall    f1
BENIGN        0.985420    0.970836  0.978074
PortScan      0.977255    0.988667  0.982928
```

Confusion matrix:

```text
[[24534   737]
 [  363 31666]]
```

These results come from the notebook's random stratified test split.

They should not be interpreted as proof of production/generalization
performance on unseen networks.

---

## 8. Known Limitations

### Dataset-specific validation

The current model was trained and evaluated on CIC-IDS2017 PortScan traffic.
It has not been independently validated against a separate external
PortScan dataset in the current implementation.

### Random train/test split

The reported 98.08% result comes from a random stratified train/test split.
Traffic flows from the same capture environment can be correlated, so this
number should be treated as the current model evaluation result rather than
a guaranteed real-world detection rate.

### Flow-level detector

The model only receives the eight flow-level fields listed in the Feature
Contract.

It does not independently maintain:

```text
source-IP history
destination-host history
unique destination-port counts
unique destination-host counts
rolling connection windows
```

Therefore the current model is a **flow-level PortScan classifier**, not a
full temporal scanner-behavior detector.

If SPECTRA later adds aggregation/window features, that requires a new model
and schema.

### Runtime feature mapping

The model was trained from CIC-style flow fields.

The SPECTRA runtime must provide equivalent feature semantics. Do not map
unrelated telemetry fields simply because their names look similar.

---

## 9. Change Rules

### Feature changes

Any change to:

- feature definitions
- feature order
- feature units
- feature calculations
- feature count
- runtime feature semantics

requires model/schema revalidation.

### Threshold changes

Changing:

```text
0.50166595
```

requires checking the new decision boundary against the trained model and
re-evaluating the resulting detector behavior.

Do not tune the threshold independently in the backend.

### Model changes

Changing the XGBoost model, model configuration, or trained artifact requires:

- a new model version
- updated feature/schema information if required
- updated evaluation results
- updated runtime artifact

The model, schema, threshold, and runtime feature builder must remain
synchronized.

---

## 10. Final Detector Contract

```text
INPUT
    ↓
Required flow telemetry
    ↓
8 exact SPECTRA PortScan features
    ↓
XGBoost
    ↓
raw model score
    ↓
threshold 0.50166595
    ↓
┌────────────────────┐
│                    │
PortScan           Benign
│                    │
└────────────────────┘
    ↓
Backend prediction/evidence contract
```

### Final files

```text
detectors/portscan/
├── portscan_detector.py
├── spectra_portscan_detector.joblib
├── spectra_portscan_feature_schema.json
└── port_scan_model.md
```

This document describes the current deployable PortScan detector contract.
The Colab notebook remains the training/development record and is not
required for runtime inference.

---

## 11. Backend Handoff Verification Checklist

| # | Handoff Requirement | Status / Verification Result |
|---|---|---|
| 1 | Exact Model Artifact | `detectors/port_scan/spectra_portscan_detector.joblib` (XGBClassifier bundle) verified loadable. |
| 2 | Exact Feature Schema/Order | `detectors/port_scan/spectra_portscan_feature_schema.json` defines 8 features in exact frozen order. |
| 3 | Preprocessing/Auxiliary Artifacts | Feature handling in `portscan_detector.py` (`build_features`), numeric coercion, NaN/Inf replacement with 0. |
| 4 | Runtime Feature Semantics | 8 raw input columns (`REQUIRED_INPUT_COLUMNS`) passed directly as XGBoost input features. |
| 5 | Threshold / Decision Rule | `0.50166595` enforced in runtime prediction. |
| 6 | Model + Detector Version | Detector version `1.0`, Model version `1.0` (XGBoost). |
| 7 | Runtime Requirements | Python 3.10+, `joblib>=1.4.0`, `xgboost>=2.0.0`, `pandas>=2.0.0`, `numpy>=1.24.0`. Tested with Python 3.11.9, XGBoost 3.2.0, Joblib 1.6.0. |
| 8 | Valid Inference Example | `PortScanDetector().predict_flow(flow)` returns standard prediction dictionary. |
| 9 | Benign Test Case | `tests/fixtures/portscan/benign_flow.json` (Score < 0.50166595, Status: `BENIGN`). |
| 10 | Suspicious/Attack Test Case | `tests/fixtures/portscan/attack_flow.json` (Score >= 0.50166595, Status: `DETECTED`, Threat: `PortScan`). |
| 11 | Output / Evidence Format | Standardized dictionary containing `status`, `threat_class`, `score_type`, `raw_score`, `threshold`, `evidence`, `context`, `detector_name`, `detector_version`, `model_name`, `model_version`, `feature_schema`. |
| 12 | State / Window Semantics | Stateless per-flow evaluation. No rolling temporal window required for model inference. |

### Integration Verification Status: **VERIFIED & READY FOR BACKEND INTEGRATION**
- Automated Test Suite: `tests/test_portscan_detector.py` (5/5 tests passed).

