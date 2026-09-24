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

No attack capture with complete packet observations is checked in. A legitimate
offline DDoS evaluation needs a provenance-recorded DDoS PCAP; a Port Scan
evaluation needs a provenance-recorded scan PCAP (for example a raw
CIC-IDS2017 PortScan scenario). Those must be analyzed offline and reported as
separate evaluations. A model prediction, if produced later, will not by
itself establish detector effectiveness or live sensor performance.

### References

- [Zeek 8 `new_packet` event](https://docs.zeek.org/en/v8.0.5/scripts/base/bif/event.bif.zeek.html)
- [Zeek packet header records](https://docs.zeek.org/en/v8.0.5/scripts/base/init-bare.zeek.html)
- [CICFlowMeter feature definitions](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java)
- [DDoS model handoff](../detectors/ddos/ddos_model.md)
- [Port Scan model handoff](../detectors/port_scan/port_scan_model.md)
