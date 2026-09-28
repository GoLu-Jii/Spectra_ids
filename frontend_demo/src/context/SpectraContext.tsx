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
import { globalDemoController } from '../demo/demoController';
import type { DemoStep } from '../demo/demoScenario';
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
  activeDetectors: string[];
  isDemoScenarioRunning: boolean;
  triggerDemoScenario: () => void;
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
  const [isDemoScenarioRunning, setIsDemoScenarioRunning] = useState<boolean>(false);

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
  const [activeDetectors, setActiveDetectors] = useState<string[]>(['ddos', 'port_scan']);

  const reconnectAttempt = useRef<number>(0);
  const socketRef = useRef<WebSocket | null>(null);

  const threatAggregatesRef = useRef<ThreatAggregate[]>(threatAggregates);
  useEffect(() => {
    threatAggregatesRef.current = threatAggregates;
  }, [threatAggregates]);

  const isDemoScenarioRunningRef = useRef<boolean>(false);
  useEffect(() => {
    isDemoScenarioRunningRef.current = isDemoScenarioRunning;
  }, [isDemoScenarioRunning]);

  const triggerDemoScenario = () => {
    if (isDemoScenarioRunningRef.current) {
      // Toggle OFF: stop scenario immediately. Incoming traffic drops to 0, threat counts remain visible.
      globalDemoController.stop();
      setIsDemoScenarioRunning(false);
      setMetrics((prev) => ({
        ...prev,
        packetsPerSec: 0,
        throughputMbps: 0,
        flowsPerSec: 0,
      }));
      setThreatAggregates((prev) =>
        prev.map((item) => ({
          ...item,
          ratePerSec: 0,
        }))
      );
      return;
    }

    // Toggle ON: start scenario
    setIsDemoScenarioRunning(true);
    setThreatAggregates(MOCK_THREAT_AGGREGATES);
    setRawAlerts([]);

    globalDemoController.start(
      (step: DemoStep) => {
        setMetrics((prev) => ({
          ...prev,
          packetsPerSec: step.packetsPerSec,
          throughputMbps: step.throughputMbps,
          flowsPerSec: step.flowsPerSec,
        }));

        if (step.threatUpdates && step.threatUpdates.length > 0) {
          setThreatAggregates((prev) =>
            prev.map((item) => {
              const update = step.threatUpdates?.find((u) => u.id === item.id);
              if (update) {
                return {
                  ...item,
                  ...update,
                  status: update.status || 'ACTIVE',
                };
              }
              return item;
            })
          );
        }

        if (step.newAlert) {
          setRawAlerts((prev) => [step.newAlert!, ...prev]);
        }
      },
      () => {
        // Continuous execution until manually toggled off
      }
    );
  };

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
            ratePerSec: Math.max(item.ratePerSec, 450),
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
      if (health.active_detectors && Array.isArray(health.active_detectors)) {
        setActiveDetectors(health.active_detectors);
      }
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

  // 2. Local Telemetry Ticker (Runs continuously to maintain active stream updates)
  useEffect(() => {
    if (!bootComplete) return;

    const interval = setInterval(() => {
      setSystemState((prev) => ({
        ...prev,
        uptimeSeconds: prev.uptimeSeconds + 1,
      }));

      // Fluctuate UI rates & recalculate active threat metrics
      const currentAggregates = threatAggregatesRef.current;
      const activeCount = currentAggregates.filter((t) => t.status === 'ACTIVE' || t.count > 0).length;
      const criticalCount = currentAggregates.filter((t) => t.severity === 'CRITICAL' && (t.status === 'ACTIVE' || t.count > 0)).length;

      if (isDemoScenarioRunningRef.current) {
        setMetrics((prev) => {
          const ppsJitter = Math.floor((Math.random() - 0.5) * 80);
          return {
            ...prev,
            packetsPerSec: Math.max(1000, prev.packetsPerSec + ppsJitter),
            activeThreatsCount: activeCount,
            criticalThreatsCount: criticalCount,
          };
        });
      } else {
        setMetrics((prev) => {
          return {
            ...prev,
            throughputMbps: 0,
            packetsPerSec: 0,
            flowsPerSec: 0,
            activeThreatsCount: activeCount,
            criticalThreatsCount: criticalCount,
          };
        });
      }

      // Continuously update active threat event counts & fluctuate stream rates ONLY while demo scenario is running
      if (isDemoScenarioRunningRef.current) {
        setThreatAggregates((prev) =>
          prev.map((item) => {
            if (item.status !== 'ACTIVE' && item.ratePerSec === 0) return item;

            // Dynamically fluctuate rate per second around baseline
            const baseRate = item.ratePerSec > 0 ? item.ratePerSec : 450;
            const jitter = Math.floor((Math.random() - 0.5) * 16);
            const currentRate = Math.max(100, Math.min(1200, baseRate + jitter));
            const countDelta = currentRate;

            return {
              ...item,
              count: item.count + countDelta,
              ratePerSec: currentRate,
              lastSeen: new Date().toISOString(),
            };
          })
        );
      } else {
        // When stopped: freeze all threat counts and set ratePerSec to 0
        setThreatAggregates((prev) =>
          prev.map((item) => (item.ratePerSec !== 0 ? { ...item, ratePerSec: 0 } : item))
        );
      }

      // Continuously increment total ingest records
      setPipelineHealth((prev) => ({
        ...prev,
        processedRecordsTotal: prev.processedRecordsTotal + Math.floor(400 + Math.random() * 150),
      }));
    }, 1000);

    return () => clearInterval(interval);
  }, [bootComplete]);

  const acknowledgeThreat = (id: string) => {
    setThreatAggregates((prev) =>
      prev.map((item) => (item.id === id ? { ...item, status: 'MONITORING', ratePerSec: 0 } : item))
    );
  };

  const resetCounters = () => {
    setThreatAggregates((prev) =>
      prev.map((item) => ({ ...item, count: 0, ratePerSec: 0, status: 'MONITORING' }))
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
        activeDetectors,
        isDemoScenarioRunning,
        triggerDemoScenario,
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
