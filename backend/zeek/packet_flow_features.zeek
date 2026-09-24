module SPECTRA;

export {
    redef enum Log::ID += { PACKET_FLOW_LOG };

    type PacketFlowRecord: record {
        ts: time &log;
        uid: string &log;
        src: addr &log;
        dst: addr &log;
        src_port: count &log;
        dst_port: count &log;
        proto: count &log;
        payload_len: count &log &optional;
        tcp_flags: count &log &optional;
        flow_complete: bool &log;
        flow_start_ts: time &log &optional;
    };
}

type FlowState: record {
    first_ts: time;
    last_ts: time;
    src: addr;
    dst: addr;
    src_port: count;
    dst_port: count;
    proto: count;
};

global flow_states: table[string] of FlowState = table();

event zeek_init() &priority=5 {
    Log::create_stream(SPECTRA::PACKET_FLOW_LOG,
                       [$columns=SPECTRA::PacketFlowRecord, $path="packet"]);
}

event new_packet(c: connection, p: pkt_hdr) {
    local src: addr = 0.0.0.0;
    local dst: addr = 0.0.0.0;
    if ( p?$ip ) {
        src = p$ip$src;
        dst = p$ip$dst;
    }
    else if ( p?$ip6 ) {
        src = p$ip6$src;
        dst = p$ip6$dst;
    }
    else
        return;

    local src_port: count = 0;
    local dst_port: count = 0;
    local proto: count = 0;
    local payload_len: count = 0;
    local has_payload_len = F;
    local tcp_flags: count = 0;
    local has_tcp_flags = F;

    if ( p?$tcp ) {
        src_port = port_to_count(p$tcp$sport);
        dst_port = port_to_count(p$tcp$dport);
        proto = 6;
        payload_len = p$tcp$dl;
        has_payload_len = T;
        tcp_flags = p$tcp$flags;
        has_tcp_flags = T;
    }
    else if ( p?$udp ) {
        src_port = port_to_count(p$udp$sport);
        dst_port = port_to_count(p$udp$dport);
        proto = 17;
        if ( p$udp$ulen >= 8 ) {
            payload_len = p$udp$ulen - 8;
            has_payload_len = T;
        }
    }
    else
        return;

    local ts = network_time();
    if ( c$uid !in flow_states ) {
        flow_states[c$uid] = [$first_ts=ts, $last_ts=ts, $src=src, $dst=dst,
                              $src_port=src_port, $dst_port=dst_port, $proto=proto];
    }
    else {
        local state = flow_states[c$uid];
        state$last_ts = ts;
        flow_states[c$uid] = state;
    }

    local row: PacketFlowRecord = [$ts=ts, $uid=c$uid, $src=src, $dst=dst,
                                   $src_port=src_port, $dst_port=dst_port,
                                   $proto=proto,
                                   $flow_complete=F];
    if ( has_payload_len )
        row$payload_len = payload_len;
    if ( has_tcp_flags )
        row$tcp_flags = tcp_flags;
    Log::write(SPECTRA::PACKET_FLOW_LOG, row);
}

event connection_state_remove(c: connection) {
    if ( c$uid !in flow_states )
        return;

    local state = flow_states[c$uid];
    Log::write(SPECTRA::PACKET_FLOW_LOG,
        [$ts=state$last_ts, $uid=c$uid, $src=state$src, $dst=state$dst,
         $src_port=state$src_port, $dst_port=state$dst_port, $proto=state$proto,
         $flow_complete=T, $flow_start_ts=state$first_ts]);
    delete flow_states[c$uid];
}
