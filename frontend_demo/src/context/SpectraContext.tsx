import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import {
  fetchHealth,
  fetchStats,
  fetchAlerts,
  getWsUrl,
  type BackendAlert,
  type BackendHealth,
  type BackendStats,
} from '../services/api';
import {
  MOCK_OPERATIONAL_METRICS,
  MOCK_PIPELINE_HEALTH,
  MOCK_SYSTEM_STATE,
  MOCK_THREAT_AGGREGATES,
} from '../mock/spectraMock';
import type {
  OperationalMetrics,
  PipelineHealth,
  SystemState,
  ThreatAggregate,
  AlertItem,
} from '../types/spectra';

interface SpectraContextType {
  bootComplete: boolean;
  setBootComplete: (complete: boolean) => void;
  systemState: SystemState;
  metrics: OperationalMetrics;
  pipelineHealth: PipelineHealth;
  threatAggregates: ThreatAggregate[];
  rawAlerts: AlertItem[];
  acknowledgeThreat: (id: string) => void;
  resetCounters: () => void;
  isBackendConnected: boolean;
}

const SpectraContext = createContext<SpectraContextType | undefined>(undefined);

const THREAT_FAMILY_MAP: Record<string, string> = {
  ddos: 'threat_ddos',
  'volumetric / protocol ddos': 'threat_ddos',
  c2: 'threat_c2',
  'botnet c2 beaconing': 'threat_c2',
  dga: 'threat_dga_dns',
  dns: 'threat_dga_dns',
  'dga + dns tunnelling': 'threat_dga_dns',
  tls: 'threat_tls',
  quic: 'threat_tls',
  'malware in encrypted sessions': 'threat_tls',
  recon: 'threat_recon',
  'port scan': 'threat_recon',
  'reconnaissance / port scan': 'threat_recon',
  exfil: 'threat_exfil',
  exfiltration: 'threat_exfil',
  'data exfiltration anomaly': 'threat_exfil',
};

export const SpectraProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [bootComplete, setBootComplete] = useState<boolean>(false);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  const [systemState, setSystemState] = useState<SystemState>({
    ...MOCK_SYSTEM_STATE,
    connectionStatus: 'CONNECTING',
  });
  const [metrics, setMetrics] = useState<OperationalMetrics>(MOCK_OPERATIONAL_METRICS);
  const [pipelineHealth, setPipelineHealth] = useState<PipelineHealth>({
    ...MOCK_PIPELINE_HEALTH,
    latencyP95Ms: 22,
    latencyP99Ms: 38,
  });
  const [threatAggregates, setThreatAggregates] = useState<ThreatAggregate[]>(MOCK_THREAT_AGGREGATES);
  const [rawAlerts, setRawAlerts] = useState<AlertItem[]>([]);

  const reconnectAttempt = useRef<number>(0);
  const socketRef = useRef<WebSocket | null>(null);

  // Helper to process incoming alert (WebSocket or REST)
  const processIncomingAlert = (alert: BackendAlert) => {
    const alertClassLower = (alert.threat_class || '').toLowerCase();
    const mappedId =
      Object.entries(THREAT_FAMILY_MAP).find(([key]) => alertClassLower.includes(key))?.[1] ||
      'threat_ddos';

    setThreatAggregates((prev) =>
      prev.map((item) => {
        if (item.id === mappedId) {
          return {
            ...item,
            count: item.count + 1,
            ratePerSec: Math.max(item.ratePerSec, 1),
            lastSeen: alert.timestamp || new Date().toISOString(),
            confidence: alert.confidence || item.confidence,
            model: alert.model || item.model,
            modelVersion: alert.model_version || item.modelVersion,
            status: 'ACTIVE',
            latestFlow: {
              src_ip: alert.src_ip || item.latestFlow.src_ip,
              src_port: alert.src_port || item.latestFlow.src_port,
              dst_ip: alert.dst_ip || item.latestFlow.dst_ip,
              dst_port: alert.dst_port || item.latestFlow.dst_port,
              protocol: alert.protocol || item.latestFlow.protocol,
            },
            evidenceSummary: alert.evidence || item.evidenceSummary,
          };
        }
        return item;
      })
    );

    setRawAlerts((prev) => {
      const exists = prev.some((a) => a.alert_id === alert.alert_id);
      if (exists) return prev;
      const newAlert: AlertItem = {
        alert_id: alert.alert_id,
        timestamp: alert.timestamp,
        flow_id: alert.flow_id,
        threat_class: alert.threat_class,
        severity: alert.severity || 'HIGH',
        confidence: alert.confidence || 0.9,
        src_ip: alert.src_ip,
        src_port: alert.src_port,
        dst_ip: alert.dst_ip,
        dst_port: alert.dst_port,
        protocol: alert.protocol,
        model: alert.model,
        model_version: alert.model_version,
        status: alert.status || 'NEW',
        evidence: alert.evidence || {},
        timing: alert.timing,
        latency_durations: alert.latency_durations,
      };
      return [newAlert, ...prev].slice(0, 100);
    });
  };

  // 1. Initial REST Fetch & WebSocket Connection Setup
  useEffect(() => {
    let active = true;
    let reconnectTimer: number;

    const syncRestData = async () => {
      const [health, stats, alerts] = await Promise.all([
        fetchHealth(),
        fetchStats(),
        fetchAlerts(),
      ]);

      if (!active) return;

      if (health || stats) {
        setIsBackendConnected(true);
        setSystemState((prev) => ({
          ...prev,
          status: health?.status === 'ok' ? 'ONLINE' : 'DEGRADED',
          connectionStatus: 'CONNECTED',
        }));
      }

      if (stats) {
        updateFromStats(stats);
      }

      if (health) {
        updateFromHealth(health);
      }

      if (alerts && alerts.length > 0) {
        alerts.forEach((alert) => processIncomingAlert(alert));
      }
    };

    const updateFromHealth = (health: BackendHealth) => {
      const zeek = health.zeek_runtime;
      setPipelineHealth((prev) => ({
        ...prev,
        telemetryState: zeek?.running ? 'STREAMING' : 'IDLE',
        processedRecordsTotal: zeek?.events_ingested || prev.processedRecordsTotal,
        stages: prev.stages.map((stage) => {
          if (stage.id === 'zeek') {
            return {
              ...stage,
              status: zeek?.running ? 'OK' : 'WARNING',
              details: `Consumed: ${zeek?.files_consumed?.length || 0} logs`,
            };
          }
          if (stage.id === 'detectors') {
            return {
              ...stage,
              status: health.model_validation_ok ? 'OK' : 'WARNING',
            };
          }
          return stage;
        }),
      }));
    };

    const updateFromStats = (stats: BackendStats) => {
      const orchestrator = stats.orchestrator;
      const latency = stats.latency;

      if (orchestrator) {
        setPipelineHealth((prev) => ({
          ...prev,
          processedRecordsTotal: orchestrator.events_processed || prev.processedRecordsTotal,
        }));
      }

      if (latency?.capture_to_alert) {
        const c2a = latency.capture_to_alert;
        const p50 = Math.round((c2a.p50 || 0.014) * 1000);
        const p95 = Math.round((c2a.p95 || 0.022) * 1000);
        const p99 = Math.round((c2a.p99 || 0.038) * 1000);

        setPipelineHealth((prev) => ({
          ...prev,
          latencyP50Ms: p50 > 0 ? p50 : prev.latencyP50Ms,
          latencyP95Ms: p95 > 0 ? p95 : prev.latencyP95Ms,
          latencyP99Ms: p99 > 0 ? p99 : prev.latencyP99Ms,
        }));
      }
    };

    // Perform initial REST sync
    syncRestData();

    // Setup WebSocket connection
    const connectWs = () => {
      if (!active) return;
      const wsUrl = getWsUrl();
      setSystemState((prev) => ({ ...prev, connectionStatus: 'CONNECTING' }));

      try {
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
          if (!active) return;
          reconnectAttempt.current = 0;
          setIsBackendConnected(true);
          setSystemState((prev) => ({ ...prev, connectionStatus: 'CONNECTED' }));
        };

        ws.onmessage = (event) => {
          if (!active) return;
          try {
            const data = JSON.parse(event.data);
            if (data && typeof data === 'object' && data.alert_id) {
              processIncomingAlert(data as BackendAlert);
            }
          } catch {
            // Ignore malformed WS frames
          }
        };

        ws.onerror = () => {
          if (!active) return;
          setSystemState((prev) => ({
            ...prev,
            wsError: 'WebSocket connection error',
          }));
        };

        ws.onclose = () => {
          if (!active) return;
          setIsBackendConnected(false);
          setSystemState((prev) => ({ ...prev, connectionStatus: 'DISCONNECTED' }));

          if (reconnectAttempt.current < 5) {
            const delay = 1000 * Math.pow(2, reconnectAttempt.current);
            reconnectAttempt.current += 1;
            setSystemState((prev) => ({ ...prev, connectionStatus: 'CONNECTING' }));
            reconnectTimer = window.setTimeout(connectWs, delay);
          } else {
            setSystemState((prev) => ({ ...prev, connectionStatus: 'DEMO_MODE' }));
          }
        };
      } catch {
        setSystemState((prev) => ({ ...prev, connectionStatus: 'DEMO_MODE' }));
      }
    };

    connectWs();

    // Periodic REST sync ticker every 3s
    const restTicker = setInterval(syncRestData, 3000);

    return () => {
      active = false;
      clearInterval(restTicker);
      window.clearTimeout(reconnectTimer);
      if (socketRef.current) socketRef.current.close();
    };
  }, []);

  // 2. Local Telemetry Ticker (Runs in parallel to ensure UI remains alive even if offline)
  useEffect(() => {
    if (!bootComplete) return;

    const interval = setInterval(() => {
      setSystemState((prev) => ({
        ...prev,
        uptimeSeconds: prev.uptimeSeconds + 1,
      }));

      // Fluctuate UI rates
      setMetrics((prev) => {
        const mbpsDelta = (Math.random() - 0.5) * 1.6;
        const ppsDelta = Math.floor((Math.random() - 0.5) * 400);
        const fpsDelta = Math.floor((Math.random() - 0.5) * 50);

        const newMbps = Math.max(15.0, Math.min(98.0, prev.throughputMbps + mbpsDelta));
        const newPps = Math.max(5000, Math.min(35000, prev.packetsPerSec + ppsDelta));
        const newFps = Math.max(800, Math.min(5000, prev.flowsPerSec + fpsDelta));

        // Calculate active and critical threat counts dynamically
        const activeCount = threatAggregates.filter((t) => t.status === 'ACTIVE' || t.count > 0).length;
        const criticalCount = threatAggregates.filter((t) => t.severity === 'CRITICAL' && t.count > 0).length;

        return {
          ...prev,
          throughputMbps: Number(newMbps.toFixed(1)),
          packetsPerSec: newPps,
          flowsPerSec: newFps,
          activeThreatsCount: activeCount,
          criticalThreatsCount: criticalCount,
        };
      });

      // If backend is disconnected, simulate subtle counter increments for active threats
      if (!isBackendConnected) {
        setThreatAggregates((prev) =>
          prev.map((item) => {
            if (item.status !== 'ACTIVE' || item.ratePerSec === 0) return item;
            const delta = item.ratePerSec + Math.floor(Math.random() * 6);
            return {
              ...item,
              count: item.count + delta,
              lastSeen: new Date().toISOString(),
            };
          })
        );

        setPipelineHealth((prev) => ({
          ...prev,
          processedRecordsTotal: prev.processedRecordsTotal + Math.floor(400 + Math.random() * 150),
        }));
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [bootComplete, isBackendConnected, threatAggregates]);

  const acknowledgeThreat = (id: string) => {
    setThreatAggregates((prev) =>
      prev.map((item) => (item.id === id ? { ...item, status: 'MONITORING' } : item))
    );
  };

  const resetCounters = () => {
    setThreatAggregates((prev) =>
      prev.map((item) => ({ ...item, count: 0, status: 'MONITORING' }))
    );
  };

  return (
    <SpectraContext.Provider
      value={{
        bootComplete,
        setBootComplete,
        systemState,
        metrics,
        pipelineHealth,
        threatAggregates,
        rawAlerts,
        acknowledgeThreat,
        resetCounters,
        isBackendConnected,
      }}
    >
      {children}
    </SpectraContext.Provider>
  );
};

export const useSpectra = (): SpectraContextType => {
  const context = useContext(SpectraContext);
  if (!context) {
    throw new Error('useSpectra must be used within a SpectraProvider');
  }
  return context;
};
