# DDoS and Port Scan packet feature acceptance

## Frozen detector contracts

The registered model inputs and order remain defined by
`backend/app/config/detectors.py` and the checked-in detector schemas. No model,
threshold, feature name, or feature order changed for this task.

| Detector | Required raw fields, in contract order |
| --- | --- |
| DDoS | `Flow Packets/s`, `Flow Bytes/s`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Fwd Packets Length Total`, `Bwd Packets Length Total`, `SYN Flag Count`, `RST Flag Count`, `ACK Flag Count`, `Packet Length Mean`, `Packet Length Std`, `Protocol` |
| Port Scan | `Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s`, `FIN Flag Count` |

## Packet source and flow direction

`backend/zeek/packet_flow_features.zeek` is the packet source adapter. It uses
Zeek's `new_packet(c, p)` event to log a `packet.log` row for each TCP/UDP
packet that enters Zeek connection processing. Each row carries the Zeek UID,
packet timestamp, packet-header endpoints and ports, numeric IP protocol,
transport payload length, and raw TCP flags when a TCP header exists. When
Zeek removes the connection state, it writes a `flow_complete=T` row carrying
the first packet's tuple and the last observed packet timestamp. The normal
Zeek `conn.log`, `dns.log`, and other logs are not rewritten.

The forward direction is the source endpoint of the first packet-log row for
that UID. Backward is the reverse endpoint tuple. The orchestrator retains the
original packet-log arrival sequence when releasing reordered events, so a
timestamp reorder does not change this direction rule. Zeek's `history` field
does not participate in direction or flag calculations.

`PacketFlowFeatureProducer` receives normalized packet events after the
existing reorder buffer. It aggregates only until the explicit flow-end row;
it does not infer flow completion from an idle timer or a `conn.log` summary.
The raw input record remains in `NormalizedEvent.raw_metadata`. The completed
feature provenance includes the Zeek UID, packet count, direction rule, source
log, and untouched flow-end record; detected alerts expose that provenance.

Zeek documents `new_packet` as a low-level, expensive event and it excludes
packets that do not pass Zeek's connection-processing checks. Therefore the
producer's totals mean Zeek-observed packet-log totals. They do not establish
that a live capture lost no packets or that this configuration meets any
throughput target.

## Exact fields produced

The producer follows the CICFlowMeter field conventions referenced by the
model handoffs: duration in microseconds, payload-byte packet lengths, and
rates over the full first-to-last packet duration. The source definitions are
visible in the upstream [CICFlowMeter BasicPacketInfo](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java)
and [BasicFlow](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
implementations. The model handoffs identify CIC-derived telemetry but do not
pin the exact training extractor version. Consequently numeric parity with the
unrecorded training ETL is not established by this implementation.

| Field | Required by | Packet source and aggregation | Type / unit |
| --- | --- | --- | --- |
| `Flow Packets/s` | DDoS, Port Scan | All observed packet rows divided by duration in seconds | float, packets/s |
| `Flow Bytes/s` | DDoS | Sum of all TCP/UDP transport payload lengths divided by duration in seconds | float, payload bytes/s |
| `Flow Duration` | DDoS, Port Scan | Last observed packet timestamp minus first observed packet timestamp | integer, microseconds |
| `Total Fwd Packets` | DDoS, Port Scan | Count of packets with the first packet's endpoint tuple | integer, packets |
| `Total Backward Packets` | DDoS, Port Scan | Count of packets with the reverse endpoint tuple | integer, packets |
| `Fwd Packets Length Total` | DDoS | Sum of transport payload lengths in the forward direction | integer, payload bytes |
| `Bwd Packets Length Total` | DDoS | Sum of transport payload lengths in the backward direction | integer, payload bytes |
| `SYN Flag Count` | DDoS | Number of TCP packet headers with SYN bit `0x02` set | integer, packets |
| `RST Flag Count` | DDoS | Number of TCP packet headers with RST bit `0x04` set | integer, packets |
| `ACK Flag Count` | DDoS | Number of TCP packet headers with ACK bit `0x10` set | integer, packets |
| `FIN Flag Count` | Port Scan | Number of TCP packet headers with FIN bit `0x01` set | integer, packets |
| `Packet Length Mean` | DDoS | Arithmetic mean of each observed packet's transport payload length | float, payload bytes |
| `Packet Length Std` | DDoS | Sample standard deviation of the same payload lengths; zero for one packet | float, payload bytes |
| `Destination Port` | Port Scan | Destination port on the first packet; direction follows the rule above | integer, port number |
| `Fwd Packets/s` | Port Scan | Forward packet count divided by full flow duration in seconds | float, packets/s |
| `Bwd Packets/s` | Port Scan | Backward packet count divided by full flow duration in seconds | float, packets/s |
| `Protocol` | DDoS | IP protocol from the packet headers: TCP `6`, UDP `17` | integer, IANA IP protocol number |

For a zero-duration flow, packet and byte rates are zero, matching the
referenced CICFlowMeter rate convention. TCP flag bits are counted per packet,
including packets with multiple bits set. UDP has no TCP header, so its TCP
flag counts are exactly zero. Other IP protocols are not passed to either
detector.

## Missing-data behavior and invocation boundary

The producer leaves the whole flow contract incomplete when it sees a missing
or invalid UID, endpoint, port, protocol, packet payload length, required TCP
flags, a changed endpoint tuple, or a missing Zeek flow-end marker. It never
fills a missing observation with zero. A zero count is used only when the
complete observed packet series contains no packet for that direction or no
TCP header for a UDP flow. A duplicate flow-end row cannot trigger a second
inference because its packet state has already been consumed.

`RuntimeOrchestrator` invokes the DDoS and Port Scan adapters only for a closed
flow with a complete producer result. `conn.log` and application logs alone
are not sent through those adapters. No generic detector windows were added.

## Score and confidence semantics

Both integrated wrappers return the positive-class `predict_proba` output as
`score_type="model_score"`; the DDoS handoff explicitly identifies it as
uncalibrated, and the Port Scan handoff does not claim calibration. The adapter
preserves that type. Alerts store it as `raw_model_score` with
`score_type="model_score"`; `confidence`, `raw_model_probability`, and
`calibrated_confidence` remain unavailable. No calibration was added.

## Validation status

## Task 12C training-feature parity audit

### Evidence boundary

The repository contains the frozen model schemas, detector-side feature
builders, model handoffs, and this packet producer. It does **not** contain
the DDoS training ETL/notebook or the Port Scan training notebook/export,
dataset hashes, CICFlowMeter version, packet-capture extraction settings, or
the training flow-construction code. The DDoS handoff identifies
“CIC-DDoS2019-derived Kaggle Parquet data”; the Port Scan handoff identifies
`CIC-IDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`.
Therefore a CIC-style field name is not treated as proof of exact training
semantics. `UNKNOWN` below means the repository cannot establish the value;
it is not an assumption about the original training data.

The producer-side values in the matrix are exact for the checked-in
implementation. A `MISMATCH` would require documented training evidence; no
such mismatch was found, so no producer formula was changed for this audit.

### DDoS parity matrix

| Feature | Training definition/math | Unit | Packet-field source | Direction | TCP/UDP | Retransmissions | Zero duration | Packet length meaning | Rate | Missing values | Training ETL/source/version | Producer comparison |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `Flow Packets/s` | CIC-style flow packet count / duration; exact formula and flow rows UNKNOWN | packets/s | Training packet/flow source UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not a length field | Exact denominator/zero rule UNKNOWN | UNKNOWN | CIC-DDoS2019-derived Kaggle Parquet; ETL/version UNKNOWN | All observed Zeek packet rows / `(last_ts-first_ts)` seconds; zero if duration is zero; parity INCOMPLETE |
| `Flow Bytes/s` | CIC-style flow bytes / duration; exact byte definition UNKNOWN | bytes/s | Training byte source UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Could be payload, IP, or other; UNKNOWN | Exact denominator/zero rule UNKNOWN | UNKNOWN | Same source; ETL/version UNKNOWN | TCP/UDP transport payload bytes / duration; zero if duration is zero; parity INCOMPLETE |
| `Flow Duration` | CIC-style flow end-start; timestamp precision and closure rule UNKNOWN | UNKNOWN, commonly microseconds | Training timestamps UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not applicable | UNKNOWN | Same source; ETL/version UNKNOWN | First-to-last observed Zeek packet timestamp in microseconds; parity INCOMPLETE |
| `Total Fwd Packets` | CIC-style forward packet count; orientation rule UNKNOWN | packets | Training flow rows UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not applicable | UNKNOWN | Same source; ETL/version UNKNOWN | Count of first-tuple direction; parity INCOMPLETE |
| `Total Backward Packets` | CIC-style backward packet count; orientation rule UNKNOWN | packets | Training flow rows UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not applicable | UNKNOWN | Same source; ETL/version UNKNOWN | Count of reverse first-tuple direction; parity INCOMPLETE |
| `Fwd Packets Length Total` | CIC-style forward packet-length sum; payload/header meaning UNKNOWN | UNKNOWN | Training packet-length field UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Payload vs IP packet length UNKNOWN | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Sum of forward TCP/UDP transport payload lengths; parity INCOMPLETE |
| `Bwd Packets Length Total` | CIC-style backward packet-length sum; payload/header meaning UNKNOWN | UNKNOWN | Training packet-length field UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Payload vs IP packet length UNKNOWN | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Sum of backward TCP/UDP transport payload lengths; parity INCOMPLETE |
| `SYN Flag Count` | CIC-style TCP SYN count; exact parser/source UNKNOWN | TCP packets | Training TCP flag source UNKNOWN | UNKNOWN | TCP semantics known by name; UDP treatment UNKNOWN | UNKNOWN | Not applicable | Not applicable | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Counts TCP `0x02` per observed packet; UDP zero; parity INCOMPLETE |
| `RST Flag Count` | CIC-style TCP RST count; exact parser/source UNKNOWN | TCP packets | Training TCP flag source UNKNOWN | UNKNOWN | TCP semantics known by name; UDP treatment UNKNOWN | UNKNOWN | Not applicable | Not applicable | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Counts TCP `0x04` per observed packet; UDP zero; parity INCOMPLETE |
| `ACK Flag Count` | CIC-style TCP ACK count; exact parser/source UNKNOWN | TCP packets | Training TCP flag source UNKNOWN | UNKNOWN | TCP semantics known by name; UDP treatment UNKNOWN | UNKNOWN | Not applicable | Not applicable | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Counts TCP `0x10` per observed packet; UDP zero; parity INCOMPLETE |
| `Packet Length Mean` | Mean of training packet-length observations; population and field meaning UNKNOWN | UNKNOWN | Training packet-length field UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Payload vs IP packet length vs other UNKNOWN | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Arithmetic mean of transport payload lengths; parity INCOMPLETE |
| `Packet Length Std` | Standard deviation of training packet lengths; sample vs population UNKNOWN | UNKNOWN | Training packet-length field UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Payload vs IP packet length vs other UNKNOWN | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | Sample standard deviation of transport payload lengths; zero for one packet; parity INCOMPLETE |
| `Protocol` | CIC protocol field; encoding/source version UNKNOWN | numeric protocol code UNKNOWN | Training flow protocol field UNKNOWN | Not applicable | UDP/TCP encoding UNKNOWN | Not applicable | Not applicable | Not applicable | Not a rate | UNKNOWN | Same source; ETL/version UNKNOWN | IP protocol `6` TCP or `17` UDP; parity INCOMPLETE |

### Port Scan parity matrix

| Feature | Training definition/math | Unit | Packet-field source | Direction | TCP/UDP | Retransmissions | Zero duration | Packet length meaning | Rate | Missing values | Training ETL/source/version | Producer comparison |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `Destination Port` | Direct CIC-IDS2017 column; flow orientation rule UNKNOWN | port number | Training flow column | UNKNOWN | UNKNOWN | Not applicable | Not applicable | Not applicable | Not a rate | Notebook numeric cleanup only; source missing behavior UNKNOWN | CIC-IDS2017 Friday PortScan CSV; notebook/extractor/version UNKNOWN | First packet destination port under first-tuple direction; parity INCOMPLETE |
| `Flow Duration` | Direct CIC-style duration column; timestamp precision and closure rule UNKNOWN | UNKNOWN, commonly microseconds | Training flow timestamps UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not a rate | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | First-to-last observed Zeek packet timestamp in microseconds; parity INCOMPLETE |
| `Total Fwd Packets` | Direct CIC-IDS2017 forward packet-count column; orientation rule UNKNOWN | packets | Training flow column | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not a rate | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | Count of first-tuple direction; parity INCOMPLETE |
| `Total Backward Packets` | Direct CIC-IDS2017 backward packet-count column; orientation rule UNKNOWN | packets | Training flow column | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Not a rate | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | Count of reverse first-tuple direction; parity INCOMPLETE |
| `Flow Packets/s` | Direct CIC-IDS2017 packet-rate column; exact source formula UNKNOWN | packets/s | Training flow column | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Exact denominator/zero rule UNKNOWN | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | All observed packet rows / duration seconds; zero if duration is zero; parity INCOMPLETE |
| `Fwd Packets/s` | Direct CIC-IDS2017 forward packet-rate column; exact source formula UNKNOWN | packets/s | Training flow column | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Exact denominator/zero rule UNKNOWN | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | Forward count / duration seconds; zero if duration is zero; parity INCOMPLETE |
| `Bwd Packets/s` | Direct CIC-IDS2017 backward packet-rate column; exact source formula UNKNOWN | packets/s | Training flow column | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | Not applicable | Exact denominator/zero rule UNKNOWN | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | Backward count / duration seconds; zero if duration is zero; parity INCOMPLETE |
| `FIN Flag Count` | Direct CIC-IDS2017 TCP FIN count; exact parser/source UNKNOWN | TCP packets | Training TCP flag source UNKNOWN | UNKNOWN | TCP semantics known by name; UDP treatment UNKNOWN | UNKNOWN | Not applicable | Not applicable | Not a rate | Notebook numeric cleanup only; source missing behavior UNKNOWN | Same CSV; notebook/extractor/version UNKNOWN | Counts TCP `0x01` per observed packet; UDP zero; parity INCOMPLETE |

### Parity result

- **DDoS feature parity: INCOMPLETE.** Exact training definitions remain
	unresolved for all listed raw fields because the training ETL, packet-length
	convention, flow-direction rule, retransmission policy, timestamp precision,
	and extractor version are absent. Runtime DDoS derived-feature formulas,
	feature order, and positive-class `model_score` semantics are documented and
	preserved; `confidence` and calibrated confidence remain unavailable.
- **Port Scan feature parity: INCOMPLETE.** The checked-in handoff identifies
	the eight direct CIC-IDS2017 columns and dataset, but the training notebook,
	flow construction, direction/retransmission policy, duration/rate formulas,
	flag source, and extractor version are absent. No producer correction is
	justified by the available evidence.

The existing `backend/tests/fixtures/zeek/dns53/conn.log` and `dns.log` remain
parser/replay fixtures. They do not contain the new per-packet records. The
bundled DNS53 PCAP is used only to check packet-log parsing and aggregation;
its one-packet benign UDP flow is not DDoS or Port Scan validation, and this
task does not run either model against it.

No attack capture is checked into the repository. The DNS53 PCAP remains only
a packet-producer sanity fixture. Task 12D's attempted external capture and
its result are documented below; DNS53 was not used for detector acceptance.

## Task 12D — real offline detector acceptance

### Acceptance status

- **DDoS: BLOCKED.** No complete source PCAP was available to Zeek, so no DDoS
  feature contract was evaluated and no model inference was run.
- **Port Scan: BLOCKED.** No complete source PCAP was available to Zeek, so no
  Port Scan feature contract was evaluated and no model inference was run.

This is a source-telemetry acquisition block, not a finding that any individual
feature is missing from the producer. The 13 DDoS inputs and 8 Port Scan inputs
remain unobserved for this acceptance attempt. Eligible flows are not
measurable; detector invocations were zero; prediction scores, confidence,
evidence, alerts, and latency were not produced. No synthetic feature vectors
or alerts were used.

### Intended capture and provenance

- Dataset: CIC-IDS2017, Friday working-hours capture, dated July 7, 2017.
- Filename: `Friday-WorkingHours.pcap`.
- Public mirror URL requested:
  `https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/Friday-WorkingHours.pcap?download=true`.
- The mirror's dataset card identifies the repository as a copy of CIC-IDS2017
  and says its `pcap/` directory contains the original PCAP files. The official
  CIC description publishes the Friday Port Scan schedule and DDoS LOIT
  interval. [Mirror dataset card](https://huggingface.co/datasets/bvsam/cic-ids-2017),
  [mirror PCAP listing](https://huggingface.co/datasets/bvsam/cic-ids-2017/tree/main/pcap),
  [official CIC-IDS2017 description](https://www.unb.ca/cic/datasets/ids-2017.html).
- Download attempt date: 2026-09-24.
- The Hub resolved the request to repository commit
  `70bac6246d99cf046186a02e1cce6883e2ffe7ea`; its response advertised a size of
  8,839,309,056 bytes. The associated Xet object identifier was
  `4afeed7141e4e6aba9707ce717746d91a8cb78cd293dff12d7241e77e5d79030`. These
  are Hub metadata values, not a SHA-256 checksum of the PCAP.
- Only 2,576,039,342 bytes were received. The transfer stopped because
  `us.aws.cdn.hf.co` could not be resolved from either the Windows host or WSL.
  The official CIC download endpoint redirected to the UNB dataset index.
- **PCAP SHA-256: unavailable.** The partial file is not a valid PCAP artifact
  for acceptance and was not parsed or hashed as if complete. It remains outside
  Git at `C:\Users\Kabir\AppData\Local\Temp\SpectraTask12D\Friday-WorkingHours.pcap`.
- The official schedule documents Port Scan activity from 13:55 through 15:29
  (including the listed scan sub-intervals) and DDoS LOIT from 15:56 to 16:16.
  These labels/time windows were not verified against packets in this attempt.

### Zeek, feature contract, and model results

- Zeek 8.0.10 is installed in WSL, but it was **not run** on the incomplete
  file. No `conn.log`, `dns.log`, `ssl.log`, `packet.log`, or filtered replay
  log was generated for this acceptance.
- The P0 factory configuration available for a future run is
  `maximum_lateness_seconds=5`, `buffer_capacity=4096`,
  `late_event_behavior=release`, `overflow_behavior=release_oldest`, and
  `window_config=null`. It was not instantiated for replay in this attempt.
- Producer version intended for the run: `zeek_new_packet_v1`, implemented in
  `backend/zeek/packet_flow_features.zeek` and
  `backend/app/detectors/packet_flow_features.py`. No per-flow input records
  were written.
- DDoS exact model inputs, predictions, positive-class `model_score`,
  calibrated confidence, evidence, alerts, failures, and latency: **not
  produced**.
- Port Scan exact model inputs, predictions, positive-class `model_score`,
  calibrated confidence, evidence, alerts, failures, and latency: **not
  produced**.
- Generated-log checksums, benchmark JSON, CPU/memory snapshots, and WebSocket
  metrics: **not available**, because Zeek and the benchmark runner were not
  run. Replay `capture_to_alert` and `capture_to_dashboard` therefore remain
  unavailable.

The training-feature parity statuses remain **INCOMPLETE** for both detectors
as recorded above. No acceptance status is claimed from model loading alone.
After a complete PCAP is available, this task must be rerun to verify actual
packets, enumerate complete ordered feature contracts, and invoke the models.

### References

- [Zeek 8 `new_packet` event](https://docs.zeek.org/en/v8.0.5/scripts/base/bif/event.bif.zeek.html)
- [Zeek packet header records](https://docs.zeek.org/en/v8.0.5/scripts/base/init-bare.zeek.html)
- [CICFlowMeter feature definitions](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java)
- [DDoS model handoff](../detectors/ddos/ddos_model.md)
- [Port Scan model handoff](../detectors/port_scan/port_scan_model.md)

## Task 12E — two-track detector acceptance

### Current status

| Detector | Model-level CIC flow acceptance | Packet-path functional exercise | Training parity | Production validation |
|---|---|---|---|---|
| DDoS | **BLOCKED** | **FUNCTIONALLY EXERCISED** | **INCOMPLETE** | **BLOCKED** |
| Port Scan | **BLOCKED** | **FUNCTIONALLY EXERCISED** | **INCOMPLETE** | **BLOCKED** |

`FUNCTIONALLY EXERCISED` in the packet-path column means the controlled
PCAP passed through Zeek, the checked-in packet logger, the packet-flow
producer, the exact detector contracts, and the existing model adapters.
It does not establish detection accuracy. The synthetic packets are not
CIC-IDS2017 and were never transmitted. Model-level CIC flow acceptance is
blocked because the requested public CSVs could not be downloaded. Training
parity remains incomplete for the reasons in the Task 12C matrices above.
No production sensor or data-diode validation was performed.

### Track A — real CIC flow-data model acceptance

The intended source is the public CIC-IDS2017 attack-specific flow CSV mirror
at [Mireu-Lab/CIC-IDS `CSV/`](https://huggingface.co/datasets/Mireu-Lab/CIC-IDS/tree/main/CSV).
Its listing contains the two requested files, shown as 77.1 MB and 76.9 MB.
The mirror card identifies these files as DDoS and PortScan flow data; the
[official CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html)
describes the labeled CSVs as CICFlowMeter analyses of the dataset traffic.

| Intended file | Exact URL requested | Result |
|---|---|---|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `https://huggingface.co/datasets/Mireu-Lab/CIC-IDS/resolve/main/CSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv?download=true` | Not downloaded |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `https://huggingface.co/datasets/Mireu-Lab/CIC-IDS/resolve/main/CSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv?download=true` | Not downloaded |

Download was attempted on 2026-09-24. Both requests redirected to
`us.aws.cdn.hf.co`, which could not be resolved from the Windows host. The
same resolution failure remained when the download command was run with the
network escalation required by the environment. No CSV bytes were accepted
as a fixture. Therefore the local exact-column inspection, row/label counts,
source SHA-256, row identifiers, deterministic attack/benign sample, adapter
invocations, scores, and predictions are all **unavailable**. No CIC flow
values were substituted from tests or handoff examples, and no inference was
run for Track A. Its result is **BLOCKED**, with zero eligible rows and zero
detector invocations. Download timestamp and SHA-256 are not applicable
because neither download completed.

### Track B — controlled offline packet-path exercise

#### Provenance and execution

- Classification: **CONTROLLED SYNTHETIC OFFLINE TRAFFIC**; this is not
  CIC-IDS2017 and is not evidence about real DDoS or scan behavior.
- A deterministic local packet-object script created an 82-packet PCAP: eight
  TCP SYN probes to distinct destination ports, eight RST/ACK replies, 64
  UDP packets of 1,200 payload bytes each at 1 ms spacing, and a separate
  closed TCP flow whose later timestamp allowed Zeek to expire the UDP flow.
  No packets were transmitted.
- PCAP path outside Git:
  `C:\Users\Kabir\AppData\Local\Temp\SpectraTask12E\controlled_synthetic_offline.pcap`.
  SHA-256: `2660a4706b2471d394e05cd668342350c380a04878511acc9440c45bbb2e8f4f`.
- Generator script outside Git:
  `C:\Users\Kabir\AppData\Local\Temp\SpectraTask12E\build_controlled_pcap.py`.
  SHA-256: `d98c02132f84610b0bfd4186e123fdadec6436fecca4ab9c00f912971931aaa8`.
- Zeek: `/opt/zeek/bin/zeek version 8.0.10`.
- Zeek command (run from the temporary artifact directory):
  `/opt/zeek/bin/zeek -C -r controlled_synthetic_offline.pcap '/mnt/c/All Projects/Spectra_ids/backend/zeek/packet_flow_features.zeek'`.
- The P0 factory `backend.app.runtime_factory:create_orchestrator` was called
  with the explicit configuration below. The existing benchmark runner then
  replayed `packet.log` in `REPLAY` / `FAST` mode through that fresh runtime.

```json
{
  "maximum_lateness_seconds": 5,
  "buffer_capacity": 4096,
  "late_event_behavior": "release",
  "overflow_behavior": "release_oldest",
  "window_config": null
}
```

Runtime evidence: Python 3.13.3, Windows 11 build 26200 host, Git `4d4bb6e5142405e293abb6ba913235527ffaed54`. The Zeek-generated logs were
outside Git:

| Log | Size | SHA-256 |
|---|---:|---|
| `packet.log` (consumed by replay; 92 records: 82 packet observations and 10 flow-end markers) | 8,445 bytes | `586fa6b3518ac54cd6d49ce5d5d761e0bdab626fce2bf5fbca475a8a24ffd589` |
| `conn.log` (10 flow records; generated, not consumed by this packet-only replay) | 1,685 bytes | `ef83538f8454ff211306ff3e68993b2c84b8f36b6f063bd51f58f22e788888e3` |
| `packet_filter.log` | 278 bytes | `c69551b83a4f90b5d79b84d9e0be744649d4257ad5f77ed3ab13ad23521f9888` |
| `weird.log` | 1,318 bytes | `9422dfc09328f4591effb9cb33cb2a86ab2c1404fef724e4c04e173ee252b0b1` |

The benchmark result, including each flow UID, every ordered adapter input,
each prediction and evidence, alert summaries, resource snapshots, and
backend metrics, is
`C:\Users\Kabir\AppData\Local\Temp\SpectraTask12E\packet_path_acceptance.json`.
Its SHA-256 is
`57ccd35191216c1a3f773f97db05c68abdc0a531fef481f02d62b203debeb318`.
The benchmark began at `2026-09-24T14:41:43.266879+00:00` and ended at
`2026-09-24T14:41:43.414623+00:00`.

#### Runtime and inference results

- Runtime read, accepted, and processed 92 packet-log records. It observed 10
  completed flows, with no parse errors, normalization errors, detector
  failures, application drops, or queue overflows. Seven records were marked
  late and released under the configured `release` policy; too-late count was
  zero. Reorder-buffer depth peaked at 66 and finished at zero.
- The DDoS adapter was invoked 10 times with all 13 raw fields in the declared
  order. Nine TCP probe/reply flows returned `DETECTED`, each with
  `model_score=0.4257778823375702` against the unchanged threshold
  `0.13920332491397858`. The remaining UDP flow returned `BENIGN` with
  `model_score=0.062230102717876434`.
- The Port Scan adapter was invoked 10 times with all 8 raw fields in the
  declared order. All returned `BENIGN`; none crossed its unchanged threshold
  `0.50166595`. The largest score was `0.3100384771823883` for destination
  port 23. Port Scan alerts generated: zero.
- Nine actual alerts were stored, all DDoS alerts on the synthetic TCP
  probe/reply flows. They and their model evidence are included in the result
  JSON. The synthetic UDP flow generated no alert. These are actual outputs
  of the existing thresholds and adapters; they were not fabricated or tuned.
- For the UDP flow, the exact DDoS raw input was: `Flow Packets/s=1015.8730158730159`,
  `Flow Bytes/s=1219047.619047619`, `Flow Duration=63000`,
  `Total Fwd Packets=64`, `Total Backward Packets=0`,
  `Fwd Packets Length Total=76800`, `Bwd Packets Length Total=0`,
  `SYN Flag Count=0`, `RST Flag Count=0`, `ACK Flag Count=0`,
  `Packet Length Mean=1200.0`, `Packet Length Std=0.0`, `Protocol=17`.
- Each of the nine TCP probe/reply flows had the same DDoS input:
  `Flow Packets/s=200.0`, `Flow Bytes/s=0.0`, `Flow Duration=10000`,
  `Total Fwd Packets=1`, `Total Backward Packets=1`,
  `Fwd Packets Length Total=0`, `Bwd Packets Length Total=0`,
  `SYN Flag Count=1`, `RST Flag Count=1`, `ACK Flag Count=1`,
  `Packet Length Mean=0.0`, `Packet Length Std=0.0`, `Protocol=6`.
- Each TCP Port Scan input had `Flow Duration=10000`, one forward and one
  backward packet, `Flow Packets/s=200.0`, `Fwd Packets/s=100.0`,
  `Bwd Packets/s=100.0`, and `FIN Flag Count=0`; the exact destination port
  and per-flow score are recorded by UID in the JSON result. The eight probe
  destination ports were 21, 22, 23, 53, 80, 443, 8080, and 8443; the
  separate flow used port 9001. The UDP Port Scan input used port 9000.
- `model_score` is the existing positive-class `predict_proba` output. It is
  uncalibrated; calibrated confidence remains unavailable. The benchmark marks
  `capture_to_alert` and `capture_to_dashboard` unavailable because historical
  packet timestamps do not measure elapsed replay wall time. This unpaced
  FAST replay is not live throughput, capture latency, or production evidence.

The packet-path track is **FUNCTIONALLY EXERCISED** for both adapters because
complete contracts reached inference. The observed DDoS detections on the
synthetic scan pattern and non-detection of the synthetic UDP flow, and the
Port Scan non-detections, are reported as outputs only. They do not establish
model accuracy, CIC behavior, or training parity.

### Remaining acceptance gaps

1. Track A needs access to the two named CIC flow CSVs from a reachable,
   provenance-preserving source. Until bytes can be inspected and hashed,
   CIC-row model acceptance remains blocked.
2. DDoS and Port Scan feature parity remains **INCOMPLETE**. The exact original
   training ETL, versions, and feature-extraction semantics are still not
   established in the repository.
3. Production validation remains **BLOCKED**. No production capture source,
   data diode, live throughput, or real attack capture was exercised.
