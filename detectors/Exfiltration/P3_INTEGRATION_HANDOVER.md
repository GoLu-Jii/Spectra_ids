# Exfiltration detector handover

## Artifacts and runtime

- Model package: `dns_exfiltration_stateful_xgb_final.pkl`
- Inference adapter: `exfiltration_adapter.py`
- Rebuild script: `train_exfiltration_model.py`
- Provenance and metrics: `exfiltration_training_metadata.json`
- Replay examples: `fixtures/exfiltration_stateful_inference_fixtures.json`
- Dependencies: `requirements.txt` (Python 3.10+, XGBoost 3.4.1)
- Model/detector version: 2.0.0-rebuilt / 2.0.0
- Decision: probability >= threshold in metadata (validation-selected F1 threshold)

## Input and state contract

Input is one ordered row from the notebook's 27-column stateful DNS feature CSV. The required schema is `input_schema` in the metadata. The selected model feature order is `feature_order` there (10 fields): `rr_count_prev20_mean`, `ttl_range_prev20_mean`, `ttl_variance_prev20_std`, `ttl_mean_prev20_mean`, `rr_name_length_prev20_mean`, `PTR_frequency_prev20_mean`, `is_PTR_record_prev20_mean`, `reverse_dns_known_prev20_mean`, `ttl_unique_count_prev20_mean`, `rr_entropy_per_length_prev20_mean`.

`ExfiltrationDetector.predict(record)` scores a record using the previous at most 20 records, excludes the current record from that context, and appends it after scoring. `reset()` clears state; instantiate or reset at each capture/client stream boundary. Initial context fields are zero. Evidence includes all 10 model inputs, class text, probability, threshold, history count and capacity. Output is `(prediction, probability, evidence)` with 0 benign and 1 exfiltration. `infer_exfiltration_csv.py input.csv output.jsonl` provides chunked inference for one upstream-generated capture CSV and resets state at file start.

## Examples and limits

Fixtures replay one benign and one suspicious held-out row and include their 20 preceding records. Both predict the expected class. Holdout accuracy and ROC-AUC are in the metadata.

The local training data are feature CSVs, not PCAPs. The packet-to-27-field DNS aggregation and enrichment pipeline (country/ASN and domain grouping) is not in this project, so direct PCAP inference is still blocked. Do not feed raw packet fields into this adapter.
