import React, { useState } from 'react';
import type { ThreatAggregate } from '../../types/spectra';

interface ThreatRowProps {
  threat: ThreatAggregate;
  onAcknowledge?: (id: string) => void;
}

export const AlertRow: React.FC<ThreatRowProps> = ({ threat, onAcknowledge }) => {
  const [expanded, setExpanded] = useState(false);

  const isCritical = threat.severity === 'CRITICAL';
  const isHigh = threat.severity === 'HIGH';

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'badge-critical';
      case 'HIGH':
        return 'badge-high';
      case 'MEDIUM':
        return 'badge-medium';
      case 'LOW':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  const formattedTime = new Date(threat.lastSeen).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div
      style={{
        ...styles.wrapper,
        borderColor: expanded
          ? isCritical ? '#FF7B4B' : '#334155'
          : '#1E2230',
        backgroundColor: expanded ? '#111420' : '#0D0F17',
      }}
    >
      {/* Clean Detection Row: Severity -> Human-Readable Threat -> Traffic Info */}
      <div style={styles.mainRow} onClick={() => setExpanded(!expanded)}>
        {/* Left: Chevron, Severity, Human-Readable Threat (Satoshi) */}
        <div style={styles.leftMeta}>
          <span style={{ ...styles.expandChevron, color: expanded ? '#F1F5F9' : '#64748B' }}>
            {expanded ? '▼' : '►'}
          </span>
          <span className={`badge ${getSeverityBadgeClass(threat.severity)}`}>
            {threat.severity}
          </span>
          <span style={styles.threatFamily}>{threat.threat_family}</span>
        </div>

        {/* Center: Live Accumulated Event Count & Rate (Satoshi labels + Monospace numbers) */}
        <div style={styles.centerCounter}>
          <span style={styles.counterLabel}>CUMULATIVE EVENTS:</span>
          <span style={{ ...styles.counterValue, color: isCritical ? '#FF7B4B' : '#F1F5F9' }}>
            {threat.count.toLocaleString()}
          </span>
          <span style={{ ...styles.rateTag, color: isCritical ? '#FF8C5F' : '#94A3B8' }}>
            ▲ +{threat.ratePerSec}/s
          </span>
        </div>

        {/* Right: Traffic Flow & Confidence (Monospace for IPs/ports/timestamps) */}
        <div style={styles.rightMeta}>
          <div style={styles.latestFlowBox}>
            <span style={styles.flowLabel}>LATEST FLOW:</span>
            <span style={styles.flowVal}>
              {threat.latestFlow.src_ip}:{threat.latestFlow.src_port} ──► {threat.latestFlow.dst_ip}:{threat.latestFlow.dst_port}
            </span>
          </div>
          <div style={styles.confidenceBox}>
            <span style={{ ...styles.confidenceVal, color: isCritical ? '#FF7B4B' : '#CBD5E1' }}>
              {(threat.confidence * 100).toFixed(1)}%
            </span>
            <span style={styles.timestamp}>{formattedTime}</span>
          </div>
        </div>
      </div>

      {/* Expanded Deep Telemetry & Evidence Payload (Monospace for technical IDs/JSON) */}
      {expanded && (
        <div style={styles.evidenceBody}>
          <div style={styles.metaGrid}>
            <div style={styles.metaItem}>
              <span style={styles.metaLabel}>THREAT VECTOR CODE:</span>
              <span style={styles.metaValMono}>{threat.threat_code}</span>
            </div>
            <div style={styles.metaItem}>
              <span style={styles.metaLabel}>DETECTOR MODEL:</span>
              <span style={styles.metaValMono}>{threat.model} (v{threat.modelVersion})</span>
            </div>
            <div style={styles.metaItem}>
              <span style={styles.metaLabel}>TARGET / MONITORED ASSET:</span>
              <span style={styles.metaVal}>{threat.asset_name || 'Production Gateway Interface'}</span>
            </div>
            <div style={styles.metaItem}>
              <span style={styles.metaLabel}>ACCUMULATED RECORD RATE:</span>
              <span style={{ ...styles.metaValMono, color: isCritical || isHigh ? '#FF7B4B' : '#CBD5E1' }}>
                {threat.count.toLocaleString()} total events ({threat.ratePerSec} pps stream)
              </span>
            </div>
          </div>

          {/* Evidence Feature Summary */}
          <div style={styles.evidenceSection}>
            <div style={styles.evidenceHeader}>EXTRACTED TELEMETRY EVIDENCE SUMMARY</div>
            <pre style={styles.jsonBox}>
              {JSON.stringify(
                {
                  latest_sample_flow: threat.latestFlow,
                  evidence_features: threat.evidenceSummary,
                  timestamp_last_seen: threat.lastSeen,
                },
                null,
                2
              )}
            </pre>
          </div>

          {/* Action Row */}
          <div style={styles.actionRow}>
            {threat.status === 'ACTIVE' && onAcknowledge && (
              <button
                type="button"
                style={styles.ackBtn}
                onClick={(e) => {
                  e.stopPropagation();
                  onAcknowledge(threat.id);
                }}
              >
                ACKNOWLEDGE THREAT VECTOR
              </button>
            )}
            <span style={styles.statusNote}>PASSIVE READ-ONLY INGEST · NON-INTERRUPTIVE MONITORING ENCLAVE</span>
          </div>
        </div>
      )}
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    border: '1px solid #1E2230',
    borderRadius: '1px',
    marginBottom: '6px',
    transition: 'all 200ms ease',
    fontFamily: 'var(--font-sans)',
  },
  mainRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '9px 14px',
    cursor: 'pointer',
    userSelect: 'none',
  },
  leftMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    minWidth: '280px',
  },
  expandChevron: {
    fontSize: '9px',
    width: '10px',
  },
  threatFamily: {
    fontSize: '13px',
    fontWeight: 600,
    fontFamily: 'var(--font-sans)',
    color: '#F1F5F9',
  },
  centerCounter: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontFamily: 'var(--font-sans)',
    backgroundColor: 'rgba(30, 41, 59, 0.3)',
    border: '1px solid #1E293B',
    padding: '4px 12px',
    borderRadius: '1px',
  },
  counterLabel: {
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    color: '#64748B',
    letterSpacing: '0.04em',
  },
  counterValue: {
    fontSize: '13px',
    fontFamily: 'var(--font-mono)',
    fontWeight: 600,
    letterSpacing: '-0.01em',
  },
  rateTag: {
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    fontWeight: 500,
  },
  rightMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
    fontFamily: 'var(--font-sans)',
  },
  latestFlowBox: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
    gap: '1px',
  },
  flowLabel: {
    fontSize: '9px',
    fontFamily: 'var(--font-sans)',
    color: '#64748B',
    letterSpacing: '0.04em',
  },
  flowVal: {
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    color: '#CBD5E1',
  },
  confidenceBox: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
    gap: '1px',
  },
  confidenceVal: {
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    fontWeight: 600,
  },
  timestamp: {
    fontSize: '9px',
    fontFamily: 'var(--font-mono)',
    color: '#64748B',
  },
  evidenceBody: {
    padding: '14px',
    borderTop: '1px solid #1E2230',
    backgroundColor: '#090A0F',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
    fontFamily: 'var(--font-sans)',
  },
  metaGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: '12px',
    fontSize: '11px',
  },
  metaItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  metaLabel: {
    color: '#64748B',
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 600,
  },
  metaVal: {
    color: '#E2E8F0',
    fontFamily: 'var(--font-sans)',
  },
  metaValMono: {
    color: '#E2E8F0',
    fontFamily: 'var(--font-mono)',
  },
  evidenceSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  evidenceHeader: {
    fontSize: '10px',
    color: '#64748B',
    fontFamily: 'var(--font-sans)',
    fontWeight: 600,
    letterSpacing: '0.04em',
  },
  jsonBox: {
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    color: '#CBD5E1',
    backgroundColor: '#0D0F17',
    border: '1px solid #1E2230',
    padding: '10px 12px',
    borderRadius: '1px',
    overflowX: 'auto',
    lineHeight: 1.4,
  },
  actionRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: '4px',
  },
  ackBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    fontWeight: 500,
    backgroundColor: 'transparent',
    color: '#CBD5E1',
    border: '1px solid #334155',
    padding: '4px 12px',
    cursor: 'pointer',
    transition: 'all 150ms',
  },
  statusNote: {
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    color: '#64748B',
    letterSpacing: '0.02em',
  },
};
