# SPECTRA DDoS Detector

## 1. Overview

The DDoS detector is a binary supervised classifier used by SPECTRA to
distinguish:

``` text
0 → Benign
1 → DDoS
```

### Current model

``` text
Model: XGBoost
Model type: XGBClassifier
Feature schema: v1.0
Feature count: 12
Decision threshold: 0.139203
```

The detector operates on flow-level network telemetry and returns a
binary DDoS decision together with the model score and feature evidence.

------------------------------------------------------------------------

## 2. Model Artifact

### Artifact

``` text
spectra_ddos_detector.joblib
```

The artifact contains:

-   trained XGBoost model
-   decision threshold
-   feature schema
-   model configuration

### XGBoost configuration

``` text
n_estimators      = 200
max_depth         = 4
learning_rate     = 0.1
subsample         = 0.8
colsample_bytree  = 0.8
eval_metric       = logloss
tree_method       = hist
random_state      = 42
n_jobs            = -1
```

### Score semantics

The model output is an **uncalibrated model score**.

It must not be presented as a calibrated probability.

Decision:

``` text
raw_score >= 0.139203 → DDoS
raw_score <  0.139203 → Benign
```

The threshold was selected using the validation set and must not be
changed without revalidation.

------------------------------------------------------------------------

## 3. Feature Contract

The model expects exactly these 12 features in this order:

``` text
1.  Flow Packets/s
2.  Flow Bytes/s
3.  Flow Duration
4.  fwd_byte_ratio
5.  packet_asymmetry
6.  byte_asymmetry
7.  syn_ratio
8.  ack_ratio
9.  rst_ratio
10. Packet Length Mean
11. packet_size_variability
12. is_udp
```

The authoritative schema is:

``` text
spectra_ddos_feature_schema.json
```

### Required raw fields

The runtime feature builder must have:

``` text
Flow Packets/s
Flow Bytes/s
Flow Duration

Total Fwd Packets
Total Backward Packets

Fwd Packets Length Total
Bwd Packets Length Total

SYN Flag Count
RST Flag Count
ACK Flag Count

Packet Length Mean
Packet Length Std

Protocol
```

### Feature formulas

Use:

``` text
EPS = 1e-9
```

``` text
total_packets =
    Total Fwd Packets + Total Backward Packets

total_bytes =
    Fwd Packets Length Total + Bwd Packets Length Total

fwd_byte_ratio =
    Fwd Packets Length Total / (total_bytes + EPS)

packet_asymmetry =
    abs(Total Fwd Packets - Total Backward Packets)
    / (total_packets + EPS)

byte_asymmetry =
    abs(Fwd Packets Length Total - Bwd Packets Length Total)
    / (total_bytes + EPS)

syn_ratio =
    SYN Flag Count / (total_packets + EPS)

ack_ratio =
    ACK Flag Count / (total_packets + EPS)

rst_ratio =
    RST Flag Count / (total_packets + EPS)

packet_size_variability =
    Packet Length Std / (Packet Length Mean + EPS)

is_udp =
    1 if Protocol == 17
    0 otherwise
```

The final model receives only the 12 features listed above.

------------------------------------------------------------------------

## 4. Inference Pipeline

``` text
Passive network telemetry
        ↓
SPECTRA upstream telemetry/feature adapter
        ↓
Required flow fields
        ↓
DDoS feature construction
        ↓
12-feature vector
        ↓
XGBoost model
        ↓
raw model score
        ↓
threshold = 0.139203
        ↓
Benign / DDoS
        ↓
standardized detector result
```

Training and runtime must preserve the same feature definitions, order,
and semantics.

------------------------------------------------------------------------

## 5. Runtime Integration

### Runtime module

``` text
ddos_detector.py
```

The module is responsible for:

-   loading the model artifact
-   loading/validating the feature schema
-   constructing the 12 features
-   running inference
-   applying the frozen threshold
-   returning the detector result

It does not contain model-training or dataset code.

### Required runtime files

``` text
detectors/ddos/
├── ddos_detector.py
├── spectra_ddos_detector.joblib
├── spectra_ddos_feature_schema.json
└── ddos_model.md
```

### Integration

The detector should receive flow telemetry from the SPECTRA
feature/telemetry layer.

Conceptually:

``` python
result = detector.predict_flow(flow)
```

For batch processing:

``` python
results = detector.predict_batch(flow_dataframe)
```

The exact runtime adapter must provide the raw fields listed in the
Feature Contract.

------------------------------------------------------------------------

## 6. Detector Output

The detector result should contain the information required by the
SPECTRA backend:

``` text
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

``` text
threat_class = "DDoS"
score_type   = "model_score"
```

The feature values used for the decision should be available as evidence
so the backend/dashboard can explain the detection.

Operational severity and overall risk scoring remain backend
responsibilities.

------------------------------------------------------------------------

## 7. Model Validation

### Training dataset

``` text
CIC-DDoS2019-derived Kaggle Parquet data
```

Final binary training matrix:

``` text
70,336 rows
12 features

Benign: 27,034
DDoS:   43,302
```

### Validation results

  Metric        XGBoost
  ----------- ---------
  Precision      0.9999
  Recall         0.9984
  F1             0.9991
  FPR            0.0002
  FNR            0.0016
  ROC-AUC        1.0000
  PR-AUC         1.0000

### Large unseen evaluation

Dataset size:

``` text
306,201 rows
```

Using the validation-derived threshold:

  Metric        XGBoost
  ----------- ---------
  Precision      0.9944
  Recall         0.3811
  F1             0.5510
  FPR            0.0106
  FNR            0.6189
  ROC-AUC        0.9333
  PR-AUC         0.9832

The large unseen evaluation shows a significant generalization gap
compared with the validation split. These metrics should be treated as
the relevant evidence when discussing current model performance.

------------------------------------------------------------------------

## 8. Inference Performance

Measured on the 306,201-row unseen feature matrix:

``` text
Total model inference:     0.238344 s
Average inference/sample:  0.000778 ms
```

Measured raw XGBoost model size:

``` text
0.26 MB
```

These measurements cover **model inference only**.

They do not represent:

``` text
packet capture
→ telemetry generation
→ feature construction
→ queueing
→ inference
→ alert creation
→ dashboard delivery
```

End-to-end capture-to-alert latency must be measured separately by
SPECTRA.

------------------------------------------------------------------------

## 9. Known Product Limitations

### No true temporal/source-IP features

The training data available for the final model did not provide the
fields required to implement:

``` text
source-IP entropy
unique source count
destination concentration
true rolling windows
```

Therefore these are not part of the current 12-feature model.

### Runtime feature mapping

The model was trained from CIC-style flow fields.

The SPECTRA runtime must provide equivalent feature semantics through
its telemetry/feature layer. The model must not be given unrelated
fields merely because their names are similar.

### Generalization

The large unseen evaluation shows substantially lower recall than the
random validation split.

The current artifact should therefore be treated as the **current
integrated detector**, not as evidence of production-grade DDoS
detection recall.

### Attack-specific validation

The current artifact has not independently validated spoofed-source DDoS
using a dedicated spoofed-source PCAP fixture.

------------------------------------------------------------------------

## 10. Change Rules

The following changes require retraining and/or revalidation:

### Feature changes

Any change to:

-   feature definitions
-   feature order
-   feature units
-   feature calculations
-   feature count
-   runtime feature semantics

requires model/schema revalidation.

### Threshold changes

Changing:

``` text
0.139203
```

requires threshold re-evaluation on validation data and updated
documentation.

### Model changes

Changing the model artifact or XGBoost configuration requires a new
model version and updated evaluation results.

The model, schema, threshold, and runtime feature builder must always
remain synchronized.

------------------------------------------------------------------------

## 11. Final Detector Contract

``` text
INPUT
    ↓
Required flow telemetry
    ↓
12 exact SPECTRA DDoS features
    ↓
XGBoost
    ↓
raw model score
    ↓
threshold 0.139203
    ↓
┌───────────────┐
│               │
DDoS          Benign
│               │
└───────────────┘
    ↓
Backend prediction/evidence contract
```

### Final files

``` text
detectors/ddos/
├── ddos_detector.py
├── spectra_ddos_detector.joblib
├── spectra_ddos_feature_schema.json
└── ddos_model.md
```

This document describes the **current deployable DDoS detector
contract**. The Kaggle notebook remains the development/training record
and is not required for runtime inference.
