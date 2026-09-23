# DNS tunnelling detector handover

## Files

- Detector wrapper: `dns_tunnelling_detector.py`
- Existing model path: `dns_tunnelling_xgb_model.pkl`
- Feature schema: `dns_tunnelling_schema.json`
- Training source: `DNS_tunnelling.ipynb`

The original artifact was corrupt. `train_dns_tunnelling_model.py` rebuilds a loadable model from workspace `l2-benign.csv` and `l2-malicious.csv`; hashes, split, runtime and holdout scores are in `dns_tunnelling_training_metadata.json`.

## Inference contract

The exact ordered feature list is `FEATURE_ORDER` in `dns_tunnelling_detector.py` and `expected_features` in `dns_tunnelling_schema.json` (29 columns). `predict()` accepts one engineered row. `predict_packets()` accepts one exchange of decoded packet metadata and applies `dns_flow_features.aggregate_dns_packets` first.

Packet records require timestamp in seconds, packet length, direction (`sent`/`received`), and optional matched response latency. `predict_pcap(path)` now reads PCAP/PCAPNG using `dpkt`, decodes classic DNS on UDP/TCP port 53 or 5353, matches DNS transaction IDs for UDP response latency, and groups by client/resolver address and port for the capture. TCP DNS segments that require reassembly are skipped. The statistics helper uses population variance/std, adjacent sorted packet-time deltas, first-seen mode on ties, and zero sentinels when intervals or matched responses are absent.

## Prediction and evidence

`0` means benign DoH and `1` means malicious DNS tunnelling. Confidence is `predict_proba(...)[0][1]`. The classification threshold is `0.50`. Supporting evidence should contain the exact 29 input feature values; the wrapper returns all of them plus the prediction label.

No minimum event count, grouping key, chronological window, environment variables, or final commit hash was recorded in the notebook. This is a per-aggregated-record detector, not a streaming window manager.

## Handover status

Fixtures: `fixtures/dns_tunnelling_inference_fixtures.json` has a benign and malicious held-out row; both replay to their expected class at threshold 0.50. The holdout is a random row split, so it does not establish capture-level generalization. A generated classic-DNS query/response PCAP smoke check confirmed parsing and 25 ms latency matching. No project PCAP was available for end-to-end validation. Encrypted DoH on port 443 is not decoded; confirm that classic DNS flow grouping matches the model's training rows before production use. Install this directory's `requirements.txt`.
