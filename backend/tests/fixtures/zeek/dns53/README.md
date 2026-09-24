# Zeek DNS53 replay fixture

These logs were produced offline from the Zeek distribution's bundled test
capture. `conn.log` and `dns.log` are default Zeek output; `packet.log` is
produced by the checked-in SPECTRA packet feature logger.

- PCAP: `/opt/zeek/share/btest/data/pcaps/dns53.pcap`
- PCAP SHA-256: `02324d91deb3853f2c2f498db36dfc7f1018946a48d2fc50e825dff1d9309a2c`
- Zeek version: `8.0.10`
- Download date: not applicable; PCAP shipped with the installed Zeek distribution
- Default-log command used for the existing `conn.log` and `dns.log`:
  `/opt/zeek/bin/zeek -r /mnt/c/Users/Kabir/AppData/Local/Temp/spectra-task11b/dns53.pcap`
- Packet-log command, run with current directory
  `/mnt/c/Users/Kabir/AppData/Local/Temp/spectra-task12b-zeek`:
  `/opt/zeek/bin/zeek -r /opt/zeek/share/btest/data/pcaps/dns53.pcap /mnt/c/All\ Projects/Spectra_ids/backend/zeek/packet_flow_features.zeek`
- `conn.log` SHA-256: `3fc3256073045497bcd66ae9e66f75965ffc221ae1d34b2a5940421b23558afa`
- `dns.log` SHA-256: `be05255d54b45663a6d0c497cd5940a88597fb93324b7267e901bcd5a474f56b`
- `packet.log` SHA-256: `d10d76524b9e9f25aed67e0bc9f383fd5fa938883839aba2fb75d7ecf14a01a7`

The existing `conn.log` and `dns.log` each contain one Zeek record. The custom
`packet.log` contains one packet observation and one flow-end marker for a
single UDP flow: protocol `17`, destination port `53`, and an observed
transport payload length of `433` bytes. The producer derives a zero-microsecond
duration from the equal capture timestamps and uses the model-source convention
of zero rates for zero-duration flows.

This benign protocol test capture is used for packet parsing and aggregation
sanity only. Neither detector is invoked against it; it is not DDoS or Port
Scan validation.
