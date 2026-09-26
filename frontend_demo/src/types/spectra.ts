export type AlertSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';
export type IngestMode = 'LIVE SPAN/TAP' | 'REPLAY PCAP';
export type ConnectionStatus = 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED' | 'DEMO_MODE';

export interface LatencyBreakdown {
  capture_to_alert: { p50: number; p95: number; p99: number; max: number };
  zeek_to_ingest: { p50: number; p95: number; p99: number; max: number };
  queue_wait: { p50: number; p95: number; p99: number; max: number };
  window_wait: { p50: number; p95: number; p99: number; max: number };
  feature_time: { p50: number; p95: number; p99: number; max: number };
  inference_time: { p50: number; p95: number; p99: number; max: number };
  delivery_time: { p50: number; p95: number; p99: number; max: number };
}

export interface SystemState {
  status: 'ONLINE' | 'OFFLINE' | 'DEGRADED';
  passiveMode: boolean;
  ingestMode: IngestMode;
  uptimeSeconds: number;
  connectionStatus: ConnectionStatus;
  wsError?: string;
  restError?: string;
}

export interface OperationalMetrics {
  throughputMbps: number;
  packetsPerSec: number;
  flowsPerSec: number;
  activeThreatsCount: number;
  criticalThreatsCount: number;
}

export interface PipelineStage {
  id: string;
  name: string;
  status: 'OK' | 'WARNING' | 'ERROR';
  details?: string;
}

export interface PipelineHealth {
  stages: PipelineStage[];
  telemetryState: 'STREAMING' | 'PAUSED' | 'IDLE';
  lossRatePct: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  latencyP99Ms: number;
  processedRecordsTotal: number;
  latencyBreakdown?: Partial<LatencyBreakdown>;
}

export interface AlertItem {
  alert_id: string;
  timestamp: string;
  flow_id?: string;
  threat_class: string;
  severity: AlertSeverity;
  confidence: number;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  model?: string;
  model_version?: string;
  feature_schema?: string;
  status: AlertStatus;
  evidence: Record<string, unknown>;
  timing?: Record<string, unknown>;
  latency_durations?: Record<string, unknown>;
  asset_id?: string;
  asset_name?: string;
}

export interface ThreatAggregate {
  id: string;
  threat_family: string;
  threat_code: string;
  severity: AlertSeverity;
  count: number;
  ratePerSec: number;
  lastSeen: string;
  confidence: number;
  model: string;
  modelVersion: string;
  status: 'ACTIVE' | 'MONITORING';
  latestFlow: {
    src_ip: string;
    src_port: number;
    dst_ip: string;
    dst_port: number;
    protocol: string;
  };
  evidenceSummary: Record<string, unknown>;
  asset_name?: string;
}
