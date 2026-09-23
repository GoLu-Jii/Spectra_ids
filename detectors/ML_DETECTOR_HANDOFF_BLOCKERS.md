# SPECTRA ML detector handoff status

Updated 2026-09-23 from the files in this workspace.

## C2 Beaconing — loadable, not production validated

- Artifact: `C2 Beaconing/botnet_c2_detector.pkl.gz`; wrapper falls back to this when the uncompressed artifact is absent. SHA-256 of the uncompressed serialized model is in `c2_model_metadata.json`.
- Model: 23-feature `RandomForestClassifier`; exact order and 0.20 decision threshold are in metadata and wrapper.
- Feature generation: chronological flow records grouped by `(SrcAddr, DstAddr)` into 300-second windows with 150-second stride; at least two flows per window. See `train_c2_model.py`.
- Provenance: exactly two inputs are present at workspace root: `botnet_42.2format` and `botnet_50 .2format` (note the space). Their SHA-256 hashes are in `c2_model_metadata.json`, and `train_c2_model.py` now resolves these paths. No training was run in this pass. `diagnose_c2_model.py` can score the existing model against the 50 file without fitting. Artifact load works but emitted a compatibility warning under scikit-learn 1.9.1; runtime is pinned to serialized version 1.6.1.
- Fixture: `fixtures/c2_capture52_inference_fixtures.json`. The benign case passes; the botnet-labeled case scores 0.0133 and is missed at threshold 0.20. Inference-only evaluation on the provided 50 file scored 167,294 windows (ROC-AUC 0.8643); at 0.20 recall was 43.13% and FPR 0.52%. A 0.10 threshold yields 75.39% recall but 4.53% FPR, so the threshold was not changed. See `c2_existing_model_validation_report.json`. Artifact provenance remains unverified, so production integration is not recommended.

## DGA — intentionally skipped

- The classifier file is 6.7 MB but fails XGBoost deserialization (`input stream corrupted`). The fitted character bigram TF-IDF vectorizer is absent.
- Per instruction, no vectorizer was trained or fabricated. The notebook-filtered NLTK lexical list is bundled and the eight base features work. `DGADetector.predict_lexical_fallback()` emits an explicit uncalibrated rule score and evidence, not model confidence; benign and suspicious examples are in `DGA/fixtures/dga_lexical_feature_examples.json`. The trained-model path remains blocked by the corrupt classifier and missing fitted vectorizer. Fallback accuracy is unvalidated.

## DNS tunnelling — model and feature-row inference ready

- Artifact: `DNS_Tunelling/dns_tunnelling_xgb_model.pkl`; rebuilt from `l2-benign.csv` and `l2-malicious.csv`. Hashes, split, versions, and holdout metrics: `dns_tunnelling_training_metadata.json`.
- Schema: 29 ordered features in `dns_tunnelling_schema.json` and `dns_tunnelling_detector.py`; threshold 0.50. The trainer follows the notebook's 200-tree, depth-6, learning-rate-0.1 XGBoost configuration.
- Runtime: `predict()` scores a feature row; `predict_packets()` computes fields from decoded packet records. `predict_pcap()` now handles classic DNS UDP/TCP 53/5353 in PCAP/PCAPNG using `dpkt`, matching UDP response latency by transaction id. It groups each client/resolver 4-tuple for the capture.
- Fixture: `fixtures/dns_tunnelling_inference_fixtures.json` has benign and malicious holdout rows and both replay to the expected class. The random row split may overstate generalization across captures.
- Remaining limit: no project PCAP was available for end-to-end validation. TLS-encrypted DoH on port 443 and segmented DNS-over-TCP are not decoded; confirm the grouping matches the training rows before production use.

## DNS Exfiltration — stateful feature-row inference ready

- Artifact: `Exfiltration/dns_exfiltration_stateful_xgb_final.pkl`, rebuilt from the local stateful feature CSVs. Input schema, artifact hash, source hashes, split and metrics: `exfiltration_training_metadata.json`.
- Adapter: `exfiltration_adapter.py`; 27 input fields, 10 model fields in exact order in metadata. Threshold is validation-selected and persisted in the artifact. State uses the previous up to 20 rows, excludes current row from the score, and resets between captures/streams.
- Fixtures: `fixtures/exfiltration_stateful_inference_fixtures.json` replays benign and suspicious held-out examples with their prior history; both pass.
- Remaining limit: source CSVs are already feature engineered. The upstream raw-PCAP-to-27-field DNS aggregation/enrichment pipeline is absent.

## Runtime packages

Each detector directory has a `requirements.txt`. Install the relevant detector requirements in a supported Python environment; do not combine conflicting detector pins without resolving them in the backend lockfile.
