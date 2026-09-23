"""PCAP/PCAPNG DNS flow decoding for classic UDP/TCP DNS traffic.

HTTPS/DoH payloads are encrypted and are intentionally not treated as decoded
DNS. Each returned packet group is one bidirectional client/resolver 4-tuple.
"""
from __future__ import annotations
from collections import defaultdict
from pathlib import Path
from typing import Iterator
import dpkt


def _read_capture(path: Path):
    stream=path.open('rb')
    magic=stream.read(4); stream.seek(0)
    try:
        reader=dpkt.pcapng.Reader(stream) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(stream)
        yield from reader
    finally: stream.close()


def _ip_packet(frame: bytes, linktype: int):
    if linktype==dpkt.pcap.DLT_EN10MB:
        eth=dpkt.ethernet.Ethernet(frame); packet=eth.data
        while isinstance(packet,dpkt.ethernet.VLANtag8021Q): packet=packet.data
        if isinstance(packet,(dpkt.ip.IP,dpkt.ip6.IP6)): return packet
    elif linktype in (dpkt.pcap.DLT_RAW, getattr(dpkt.pcap,'DLT_RAW_ALT',101)):
        version=frame[0]>>4
        return dpkt.ip.IP(frame) if version==4 else dpkt.ip6.IP6(frame) if version==6 else None
    elif linktype==dpkt.pcap.DLT_LINUX_SLL:
        packet=dpkt.sll.SLL(frame).data
        if isinstance(packet,(dpkt.ip.IP,dpkt.ip6.IP6)): return packet
    return None


def iter_dns_packet_groups(path: str|Path) -> Iterator[list[dict[str,object]]]:
    """Decode DNS packets, pair response latency, and group by client/resolver ports."""
    capture=Path(path)
    if not capture.is_file(): raise FileNotFoundError(capture)
    try:
        with capture.open('rb') as stream:
            magic=stream.read(4); stream.seek(0)
            reader=dpkt.pcapng.Reader(stream) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(stream)
            linktype=reader.datalink()
    except (ValueError,dpkt.NeedData) as exc:
        raise ValueError(f'Unsupported or invalid PCAP input: {capture}') from exc
    groups:dict[tuple[str,str,int,int],list[dict[str,object]]]=defaultdict(list)
    pending:dict[tuple[str,str,int,int,int],float]={}
    for timestamp,raw in _read_capture(capture):
        try: ip=_ip_packet(raw,linktype)
        except (dpkt.UnpackError,ValueError,IndexError): continue
        if ip is None: continue
        if isinstance(ip,dpkt.ip.IP): src,dst=dpkt.utils.inet_to_str(ip.src),dpkt.utils.inet_to_str(ip.dst)
        else: src,dst=dpkt.utils.inet_to_str(ip.src),dpkt.utils.inet_to_str(ip.dst)
        if isinstance(ip.data,dpkt.udp.UDP):
            transport=ip.data; srcport,dstport=int(transport.sport),int(transport.dport); payload=bytes(transport.data)
        elif isinstance(ip.data,dpkt.tcp.TCP):
            transport=ip.data; srcport,dstport=int(transport.sport),int(transport.dport); payload=bytes(transport.data)
            # DNS over TCP is length-prefixed. Reassembly across TCP segments is not attempted.
            if len(payload)>=2:
                declared=int.from_bytes(payload[:2],'big')
                if declared<=len(payload)-2: payload=payload[2:2+declared]
                else: continue
            else: continue
        else: continue
        if srcport not in (53,5353) and dstport not in (53,5353): continue
        try: dns=dpkt.dns.DNS(payload)
        except (dpkt.UnpackError,ValueError): continue
        if int(dns.qr)==0:
            client,resolver,cport,rport=src,dst,srcport,dstport
            key=(client,resolver,cport,rport)
            pending[(client,resolver,cport,rport,int(dns.id))]=float(timestamp)
            direction='sent'; latency=None
        else:
            client,resolver,cport,rport=dst,src,dstport,srcport
            key=(client,resolver,cport,rport)
            start=pending.pop((client,resolver,cport,rport,int(dns.id)),None)
            direction='received'; latency=max(float(timestamp)-start,0.0) if start is not None else None
        groups[key].append({'timestamp':float(timestamp),'length':float(len(raw)),'direction':direction,'response_time':latency,'client':client,'resolver':resolver,'client_port':cport,'resolver_port':rport})
    yield from groups.values()
