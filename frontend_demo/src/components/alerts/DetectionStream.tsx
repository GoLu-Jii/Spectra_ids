import React, { useState } from 'react';
import { useSpectra } from '../../context/SpectraContext';
import type { AlertSeverity } from '../../types/spectra';
import { AlertRow } from './AlertRow';

export const DetectionStream: React.FC = () => {
  const { threatAggregates, acknowledgeThreat, resetCounters } = useSpectra();
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const filteredThreats = threatAggregates.filter((t) => {
    if (severityFilter === 'ALL') return true;
    return t.severity === (severityFilter as AlertSeverity);
  });

  const totalEventsSum = threatAggregates.reduce((acc, t) => acc + t.count, 0);

  return (
    <section style={styles.section} aria-label="Live Aggregated Threat Stream">
      {/* Stream Controls Bar */}
      <div style={styles.controlsBar}>
        <div style={styles.leftControls}>
          <div style={styles.streamTitleGroup}>
            <span className="animate-pulse" style={styles.liveDot} />
            <span style={styles.sectionTitle}>LIVE THREAT MATRIX & AGGREGATED ATTACK VECTORS</span>
          </div>
          <span style={styles.countBadge}>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{totalEventsSum.toLocaleString()}</span> TOTAL EVENTS
          </span>
        </div>

        <div style={styles.rightControls}>
          {/* Severity Filter */}
          <div style={styles.filterGroup}>
            <label style={styles.filterLabel} htmlFor="severity-select">FILTER:</label>
            <select
              id="severity-select"
              style={styles.filterSelect}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="ALL">ALL SEVERITIES</option>
              <option value="CRITICAL">CRITICAL ONLY</option>
              <option value="HIGH">HIGH ONLY</option>
              <option value="MEDIUM">MEDIUM ONLY</option>
              <option value="LOW">LOW ONLY</option>
            </select>
          </div>

          <button
            type="button"
            style={styles.clearBtn}
            onClick={resetCounters}
            title="Reset accumulated threat counters"
          >
            RESET COUNTERS
          </button>
        </div>
      </div>

      {/* Stream Content: High-Density Aggregated Threat Rows */}
      <div style={styles.streamContainer}>
        {filteredThreats.length === 0 ? (
          <div style={styles.emptyState}>
            <span className="animate-pulse" style={styles.emptyDot} />
            <span style={styles.emptyText}>NO ACTIVE THREAT VECTORS MATCHING FILTER</span>
            <span style={styles.emptySubText}>Passive telemetry ingest active — monitoring network flows on SPAN/TAP mirror</span>
          </div>
        ) : (
          filteredThreats.map((threat) => (
            <AlertRow
              key={threat.id}
              threat={threat}
              onAcknowledge={acknowledgeThreat}
            />
          ))
        )}
      </div>
    </section>
  );
};

const styles: Record<string, React.CSSProperties> = {
  section: {
    flexGrow: 1,
    padding: '14px 18px',
    backgroundColor: '#090A0F',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    userSelect: 'none',
  },
  controlsBar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '10px',
    paddingBottom: '8px',
    borderBottom: '1px solid #1E2230',
    fontFamily: 'var(--font-sans)',
  },
  leftControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '14px',
  },
  streamTitleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  liveDot: {
    width: '5px',
    height: '5px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
  sectionTitle: {
    fontSize: '13px',
    fontWeight: 600,
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.04em',
    color: '#F1F5F9',
  },
  countBadge: {
    fontSize: '11px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 500,
    color: '#CBD5E1',
    backgroundColor: 'rgba(30, 41, 59, 0.4)',
    border: '1px solid #1E293B',
    padding: '2px 8px',
    borderRadius: '1px',
    letterSpacing: '0.04em',
  },
  rightControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  filterGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  filterLabel: {
    fontSize: '11px',
    color: '#64748B',
    fontFamily: 'var(--font-sans)',
    fontWeight: 600,
  },
  filterSelect: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    color: '#CBD5E1',
    backgroundColor: '#0D0F17',
    border: '1px solid #1E2230',
    padding: '3px 8px',
    borderRadius: '1px',
    outline: 'none',
    cursor: 'pointer',
  },
  clearBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    color: '#64748B',
    backgroundColor: 'transparent',
    border: '1px solid #1E2230',
    padding: '3px 10px',
    borderRadius: '1px',
    cursor: 'pointer',
    letterSpacing: '0.02em',
  },
  streamContainer: {
    flexGrow: 1,
    overflowY: 'auto',
    paddingRight: '4px',
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '80px 20px',
    backgroundColor: '#0D0F17',
    border: '1px dashed #1E2230',
    borderRadius: '1px',
    gap: '10px',
    fontFamily: 'var(--font-sans)',
  },
  emptyDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
  emptyText: {
    fontSize: '13px',
    fontWeight: 600,
    color: '#F1F5F9',
    letterSpacing: '0.04em',
  },
  emptySubText: {
    fontSize: '11px',
    color: '#64748B',
  },
};
