# C2 beaconing detector handover

## Files

- Detector: `c2_beaconing_detector.py`
- Training/export source: `train_c2_model.py`
- Intended training artifact: `botnet_c2_detector.pkl`
- Published artifact: `botnet_c2_detector.pkl.gz`; wrapper loads this gzip artifact if the uncompressed file is absent.

The saved artifact is a 23-feature Random Forest model. `c2_model_metadata.json` records its hash, serialized scikit-learn version, and SHA-256 hashes for the two available workspace-root inputs: `botnet_42.2format` and `botnet_50 .2format` (the second filename includes a space). The trainer now resolves those two local paths by default. This pass did not retrain the model; artifact parameters still differ from the checked-in trainer, so file provenance is recorded but not proven.

## Inference contract

Input is a chronological list of at least 2 flow dictionaries for one `(SrcIP, DstIP)` conversation. Required keys are `start_time_unix`; `bytes`, `pkts`, protocol, and reverse-direction fields are supported with defaults. The wrapper sorts by `start_time_unix` before calculating features.

The exact model feature order is:

`Dur`, `Pkts`, `Bytes`, `IAT`, `IAT_Variance`, `IAT_Std`, `Bytes_Variance`, `Bytes_Per_Packet`, `Proto_esp`, `Proto_icmp`, `Proto_igmp`, `Proto_ipv6`, `Proto_ipv6-icmp`, `Proto_ipx/spx`, `Proto_pim`, `Proto_rarp`, `Proto_rtcp`, `Proto_rtp`, `Proto_tcp`, `Proto_udp`, `Proto_udt`, `Proto_unas`, `FlowDir_Reverse`.

IAT is calculated from consecutive sorted timestamps. `Dur`, `Pkts`, and `Bytes` are window totals; IAT and byte variance use population variance. Protocol columns are one-hot indicators and `FlowDir_Reverse` is a boolean indicator. The training pipeline uses 300-second windows with a 150-second step and groups by `(SrcAddr, DstAddr)`; windows with fewer than 2 flows are skipped. P3 must preserve chronological ordering before windowing.

No scaling or encoding is applied. In the wrapper, missing byte and packet counts default to zero; protocol and reverse-direction fields also have safe defaults. The trainer derives labels from `Label` and drops source/destination identifiers after grouping.

## Prediction and evidence

`0` means normal and `1` means botnet C2. Confidence is the Random Forest malicious-class probability. The integration and training evaluation threshold is `0.20`.

Evidence returned by the wrapper includes mean IAT, IAT variance, IAT coefficient of variation, flow count, window duration, and a textual timing summary. P3 should also retain the source/destination conversation key used for grouping.

The checked inference examples are in `fixtures/c2_capture52_inference_fixtures.json`. The benign example is classified benign. The botnet-labeled example is a false negative at the 0.20 threshold; do not promote this model as a validated production C2 detector until capture-level validation is complete. Install `requirements.txt` with Python 3.10–3.13 to match serialized scikit-learn 1.6.1.

`diagnose_c2_model.py` scored the existing artifact against the provided 50 file without fitting or modifying the model: 167,294 windows, ROC-AUC 0.8643. At the production threshold 0.20, accuracy was 97.48%, false-positive rate 0.52%, and malicious recall 43.13%. At 0.10, recall rose to 75.39% while false-positive rate rose to 4.53%; threshold 0.20 remains unchanged. Full confusion counts and feature importances are in `c2_existing_model_validation_report.json`. The notebook designates the 50 file as validation, but independence from the saved model cannot be proven because artifact provenance is incomplete.
