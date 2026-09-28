import type { AlertItem, ThreatAggregate } from '../types/spectra';

export interface DemoStep {
  delayMs: number;
  packetsPerSec: number;
  throughputMbps: number;
  flowsPerSec: number;
  threatUpdates?: Partial<ThreatAggregate>[];
  newAlert?: AlertItem;
}

export const DEMO_SCENARIO_STEPS: DemoStep[] = [
  // Step 0: Traffic begins increasing (t=0s -> 1.5s)
  {
    delayMs: 1500,
    packetsPerSec: 8400,
    throughputMbps: 26.8,
    flowsPerSec: 1240,
  },
  // Step 1: Telemetry rises to ~14.2K pps (t=3.0s)
  {
    delayMs: 1500,
    packetsPerSec: 14200,
    throughputMbps: 42.1,
    flowsPerSec: 1810,
  },
  // Step 2: Volumetric DDoS Detection Appears (t=4.5s)
  {
    delayMs: 1500,
    packetsPerSec: 14600,
    throughputMbps: 44.8,
    flowsPerSec: 1860,
    threatUpdates: [
      {
        id: 'threat_ddos',
        status: 'ACTIVE',
        count: 14820,
        ratePerSec: 450,
        confidence: 0.942,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-DDoS-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-ddos-syn-01',
      threat_class: 'Volumetric / Protocol DDoS',
      severity: 'CRITICAL',
      confidence: 0.942,
      src_ip: '192.168.1.105',
      src_port: 44320,
      dst_ip: '10.0.0.1',
      dst_port: 80,
      protocol: 'TCP',
      model: 'ddos_xgb',
      model_version: '1.2',
      status: 'NEW',
      evidence: {
        syn_ratio: 0.984,
        byte_rate_bytes_per_sec: 2100000,
        flow_duration_sec: 1.2,
        packet_count: 14200,
        heuristics_triggered: ['SYN_BURST_EXCEEDED', 'LOW_DST_PORT_ENTROPY'],
      },
    },
  },
  // Step 3: Reconnaissance / Port Scan Detection Appears (t=7.0s)
  {
    delayMs: 2500,
    packetsPerSec: 15100,
    throughputMbps: 47.2,
    flowsPerSec: 1940,
    threatUpdates: [
      {
        id: 'threat_recon',
        status: 'ACTIVE',
        count: 420,
        ratePerSec: 85,
        confidence: 0.832,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-RECON-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-recon-scan-02',
      threat_class: 'Reconnaissance / Port Scan',
      severity: 'MEDIUM',
      confidence: 0.832,
      src_ip: '192.168.2.14',
      src_port: 61002,
      dst_ip: '10.0.1.55',
      dst_port: 22,
      protocol: 'TCP',
      model: 'recon_scan_detector',
      model_version: '1.0',
      status: 'NEW',
      evidence: {
        unique_dst_ports: 420,
        scan_rate_ports_per_sec: 85,
        scan_type: 'SYN_STEALTH_SCAN',
      },
    },
  },
  // Step 4: Botnet C2 Beaconing Appears (t=9.5s)
  {
    delayMs: 2500,
    packetsPerSec: 14800,
    throughputMbps: 45.6,
    flowsPerSec: 1890,
    threatUpdates: [
      {
        id: 'threat_c2',
        status: 'ACTIVE',
        count: 180,
        ratePerSec: 32,
        confidence: 0.914,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-C2-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-c2-beacon-03',
      threat_class: 'Botnet C2 Beaconing',
      severity: 'HIGH',
      confidence: 0.914,
      src_ip: '10.0.4.12',
      src_port: 52144,
      dst_ip: '185.220.101.5',
      dst_port: 443,
      protocol: 'TCP',
      model: 'c2_beacon_rf',
      model_version: '1.0',
      status: 'NEW',
      evidence: {
        inter_arrival_time_std_dev: 0.042,
        beacon_periodicity_sec: 30.0,
        callback_jitter_ms: 14,
      },
    },
  },
  // Step 5: DGA + DNS Tunnelling Appears (t=12.0s)
  {
    delayMs: 2500,
    packetsPerSec: 15300,
    throughputMbps: 48.1,
    flowsPerSec: 1980,
    threatUpdates: [
      {
        id: 'threat_dga_dns',
        status: 'ACTIVE',
        count: 310,
        ratePerSec: 45,
        confidence: 0.785,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-DNS-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-dns-tunnel-04',
      threat_class: 'DGA + DNS Tunnelling',
      severity: 'MEDIUM',
      confidence: 0.785,
      src_ip: '10.0.2.88',
      src_port: 60124,
      dst_ip: '8.8.8.8',
      dst_port: 53,
      protocol: 'UDP',
      model: 'dns_tunnel_detector',
      model_version: '1.1',
      status: 'NEW',
      evidence: {
        subdomain_entropy: 4.82,
        query_length_bytes: 184,
      },
    },
  },
  // Step 6: Malware in Encrypted Sessions Appears (t=14.5s)
  {
    delayMs: 2500,
    packetsPerSec: 14900,
    throughputMbps: 46.2,
    flowsPerSec: 1910,
    threatUpdates: [
      {
        id: 'threat_tls',
        status: 'ACTIVE',
        count: 95,
        ratePerSec: 22,
        confidence: 0.908,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-TLS-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-tls-malware-05',
      threat_class: 'Malware in Encrypted Sessions',
      severity: 'HIGH',
      confidence: 0.908,
      src_ip: '10.0.5.11',
      src_port: 54100,
      dst_ip: '198.51.100.44',
      dst_port: 443,
      protocol: 'TCP',
      model: 'tls_malware_detector',
      model_version: '1.1',
      status: 'NEW',
      evidence: {
        ja3_hash: '771fd2b5e201d0583167070864617168',
        cert_validity_days: 1,
      },
    },
  },
  // Step 7: Data Exfiltration Anomaly Appears (t=17.0s)
  {
    delayMs: 2500,
    packetsPerSec: 15400,
    throughputMbps: 48.8,
    flowsPerSec: 2010,
    threatUpdates: [
      {
        id: 'threat_exfil',
        status: 'ACTIVE',
        count: 640,
        ratePerSec: 68,
        confidence: 0.894,
        lastSeen: new Date().toISOString(),
      },
    ],
    newAlert: {
      alert_id: `ALT-EXFIL-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString(),
      flow_id: 'flow-exfil-data-06',
      threat_class: 'Data Exfiltration Anomaly',
      severity: 'HIGH',
      confidence: 0.894,
      src_ip: '10.0.1.95',
      src_port: 49200,
      dst_ip: '203.0.113.88',
      dst_port: 443,
      protocol: 'TCP',
      model: 'exfil_stat',
      model_version: '1.0',
      status: 'NEW',
      evidence: {
        outbound_bytes: 48291000,
        transfer_rate_mbps: 14.2,
      },
    },
  },
];
