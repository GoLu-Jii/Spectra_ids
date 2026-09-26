export const getApiBaseUrl = (): string => {
  return import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
};

export const getWsUrl = (): string => {
  if (import.meta.env.VITE_WS_URL) return import.meta.env.VITE_WS_URL;
  const base = getApiBaseUrl().replace(/^http/, 'ws').replace(/\/$/, '');
  return `${base}/ws`;
};

export interface BackendHealth {
  status: string;
  service_started?: boolean;
  service_ready?: boolean;
  worker_alive?: boolean;
  model_validation_ok?: boolean;
  storage_ok?: boolean;
  runtime_mode?: string;
  active_detectors?: string[];
  zeek_runtime?: {
    runtime_mode?: string;
    zeek_source_available?: boolean;
    files_consumed?: string[];
    events_ingested?: number;
    normalization_errors?: number;
    source_errors?: number;
    running?: boolean;
    [key: string]: unknown;
  };
  detector_health?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface LatencyMetric {
  p50?: number;
  p95?: number;
  p99?: number;
  max?: number;
}

export interface BackendStats {
  orchestrator?: {
    events_received?: number;
    events_processed?: number;
    detector_invocations?: number;
    detector_failures?: number;
    alerts_produced?: number;
  };
  latency?: Record<string, LatencyMetric>;
  alerts?: { count?: number };
  websocket?: Record<string, unknown>;
  zeek_runtime?: Record<string, unknown>;
}

export interface BackendAlert {
  alert_id: string;
  timestamp: string;
  flow_id?: string;
  threat_class: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  model?: string;
  model_version?: string;
  feature_schema?: string;
  status?: 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';
  evidence?: Record<string, unknown>;
  timing?: Record<string, unknown>;
  latency_durations?: Record<string, unknown>;
  asset_id?: string;
  asset_name?: string;
}

export async function fetchHealth(): Promise<BackendHealth | null> {
  try {
    const res = await fetch(`${getApiBaseUrl()}/health`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchStats(): Promise<BackendStats | null> {
  try {
    const res = await fetch(`${getApiBaseUrl()}/stats`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchAlerts(): Promise<BackendAlert[]> {
  try {
    const res = await fetch(`${getApiBaseUrl()}/alerts`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

export async function fetchAlertDetail(alertId: string): Promise<BackendAlert | null> {
  try {
    const res = await fetch(`${getApiBaseUrl()}/alerts/${encodeURIComponent(alertId)}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}
