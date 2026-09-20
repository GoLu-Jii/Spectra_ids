# Exfiltration detector handover

## Files

- Feature adapter: `the-SHIELD/backend/exfiltration_features.py`
- PCAP adapter: `the-SHIELD/backend/exfiltration_pcap.py`
- Model artifact: `the-SHIELD/ml_engine/exfilteration/dns_exfiltration_stateful_xgb_final.pkl`
- Shared feature catalog: `the-SHIELD/docs/detector_features.json`

## Inference contract

The detector consumes one normalized flow at a time. The adapter builds the model row from `NormalizedEvent` and keeps a history of the previous 100 records for stateful count features. The model input must contain exactly 187 columns in the order expected by the saved artifact.

Required flow values are:

- Positive `duration`, `orig_pkts`, and `resp_pkts`.
- `orig_bytes`, `resp_bytes`, `service`, `conn_state`, and `proto`.
- Numeric `rate`, `trans_depth`, `response_body_len`, `is_ftp_login`, `ct_ftp_cmd`, and `ct_flw_http_mthd` in the normalized event or its raw fields.
- Packet metadata under `raw["exfiltration_packet"]` for every field listed in `detector_features.json`.

The adapter derives `sload = sbytes * 8 / dur`, `dload = dbytes * 8 / dur`, `smean = sbytes / spkts`, and `dmean = dbytes / dpkts`. It then one-hot encodes `proto`, `service`, and `state`, reindexes to the artifact feature order, and fills absent one-hot columns with zero. Missing semantic or packet values are rejected; they are not fabricated.

## Feature groups

The numeric UNSW-NB15-style fields are `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `smean`, `dmean`, `trans_depth`, `response_body_len`, `is_ftp_login`, `ct_ftp_cmd`, `ct_flw_http_mthd`, the 15 packet fields, and the nine history fields. `proto`, `service`, and `state` are categorical inputs expanded into the artifact's `proto_*`, `service_*`, and `state_*` columns. The exact categorical vocabulary and order must come from the model artifact; the shared JSON records this as an artifact-generated expansion.

History fields are `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `ct_src_ltm`, `ct_srv_dst`, and `is_sm_ips_ports`. History is scoped to the adapter instance and capped at 100 records.

## Prediction and evidence

The deployed detector uses threshold `0.30`. `0` is benign and `1` is exfiltration. The runtime returns prediction, confidence, and label; the orchestrator adds the threshold and prepared feature evidence to the alert.

PCAP conversion is passive and supports TCP and UDP. It derives directional bytes, packet counts, TTL, TCP timing, sequence, acknowledgement, and window metadata. PCAP flows without enough information for the complete feature contract are rejected by the adapter instead of being scored with invented values.

## Handover status

The runtime adapter and integration tests document the 187-feature contract and threshold. The model wrapper module is not present in this checkout, and the artifact requires XGBoost to inspect its serialized feature names. Install the backend requirements and verify `expected_features` against the artifact before changing the categorical vocabulary or deploying a replacement model.