import React, { useState, useEffect } from 'react';
import { useSpectra } from '../../context/SpectraContext';
import { Sparkline } from '../common/Sparkline';

export const MetricStrip: React.FC = () => {
  const { metrics } = useSpectra();

  // Historical array for live packet rate sparkline
  const [packetHistory, setPacketHistory] = useState<number[]>([
    12000, 13200, 14100, 13800, 14500, 14200, 14250
  ]);

  useEffect(() => {
    setPacketHistory((prev) => [...prev.slice(1), metrics.packetsPerSec]);
  }, [metrics.packetsPerSec]);

  const hasCritical = metrics.criticalThreatsCount > 0;
  const hasActive = metrics.activeThreatsCount > 0;

  return (
    <section style={styles.container} aria-label="Operational Telemetry Strip">
      {/* Key Metric 1: Packet Rate */}
      <div style={styles.cardCell}>
        <div style={styles.cellHeader}>
          <span style={styles.cellLabel}>PACKET RATE</span>
          <span style={styles.cellTrend}>▲ +5.1%</span>
        </div>
        <div style={styles.cellBody}>
          <div style={styles.valueGroup}>
            <span style={styles.cellValue}>{(metrics.packetsPerSec / 1000).toFixed(1)}K</span>
            <span style={styles.cellUnit}>pps</span>
          </div>
          <Sparkline data={packetHistory} color="#FF7B4B" width={90} height={22} />
        </div>
      </div>

      {/* Key Metric 2: Active Threats */}
      <div
        style={{
          ...styles.cardCell,
          borderColor: hasCritical ? 'rgba(255, 123, 75, 0.4)' : '#2B2C34',
          backgroundColor: hasCritical ? 'rgba(255, 123, 75, 0.08)' : '#1C1C21',
        }}
      >
        <div style={styles.cellHeader}>
          <span style={{ ...styles.cellLabel, color: hasActive ? '#F1F5F9' : '#8A8D9B' }}>
            ACTIVE THREATS
          </span>
          <span
            className={hasCritical ? 'animate-pulse' : ''}
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: hasCritical ? '#FF7B4B' : hasActive ? '#FF8C5F' : '#5A5D6B',
            }}
          />
        </div>
        <div style={styles.cellBody}>
          <div style={styles.valueGroup}>
            <span style={{ ...styles.cellValue, color: hasCritical ? '#FF7B4B' : '#F1F5F9' }}>
              {metrics.activeThreatsCount}
            </span>
            <span style={{ ...styles.cellSubText, color: hasCritical ? '#FF7B4B' : '#CBD5E1' }}>
              {hasCritical ? `(${metrics.criticalThreatsCount} CRITICAL)` : 'MONITORED'}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, 1fr)',
    gap: '12px',
    backgroundColor: '#141417',
    borderBottom: '1px solid #2B2C34',
    padding: '8px 16px',
    fontFamily: 'var(--font-sans)',
    userSelect: 'none',
  },
  cardCell: {
    backgroundColor: '#1C1C21',
    border: '1px solid #2B2C34',
    borderRadius: '4px',
    padding: '8px 14px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    gap: '4px',
    transition: 'all 150ms ease',
  },
  cellHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  cellLabel: {
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    letterSpacing: '0.04em',
    color: '#8A8D9B',
  },
  cellTrend: {
    fontSize: '9px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    color: '#FF7B4B',
  },
  cellBody: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  valueGroup: {
    display: 'flex',
    alignItems: 'baseline',
    gap: '4px',
  },
  cellValue: {
    fontSize: '18px',
    fontFamily: 'var(--font-mono)',
    fontWeight: 700,
    color: '#F1F5F9',
    letterSpacing: '-0.02em',
  },
  cellUnit: {
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    color: '#8A8D9B',
  },
  cellSubText: {
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 600,
    marginLeft: '4px',
  },
};
