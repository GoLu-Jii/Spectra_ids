import React from 'react';
import { useSpectra } from '../../context/SpectraContext';

export const Header: React.FC = () => {
  const { systemState, isBackendConnected } = useSpectra();

  const connLabel = isBackendConnected
    ? 'LIVE WEBSOCKET'
    : systemState.connectionStatus === 'CONNECTING'
    ? 'RECONNECTING'
    : 'STANDALONE DEMO';

  return (
    <header style={styles.header}>
      {/* Brand */}
      <div style={styles.leftSection}>
        <span style={styles.brandTitle}>SPECtRA</span>
      </div>

      {/* Central System Architecture Indicator */}
      <div style={styles.centerSection}>
        <div style={styles.passiveBadge}>
          <span style={styles.passiveDot} />
          <span>PASSIVE MONITORING ENCLAVE · NO RETURN PATH</span>
        </div>
      </div>

      {/* Right Section: Connection Status Badge */}
      <div style={styles.rightSection}>
        <div style={styles.statusPill}>
          <span
            className={isBackendConnected ? 'animate-pulse' : ''}
            style={{
              ...styles.statusDot,
              backgroundColor: isBackendConnected ? '#10B981' : '#FF7B4B',
            }}
          />
          <span>{connLabel}</span>
        </div>
      </div>
    </header>
  );
};

const styles: Record<string, React.CSSProperties> = {
  header: {
    height: '44px',
    backgroundColor: '#141417',
    borderBottom: '1px solid #2B2C34',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 20px',
    fontFamily: 'var(--font-sans)',
    userSelect: 'none',
  },
  leftSection: {
    display: 'flex',
    alignItems: 'center',
  },
  brandTitle: {
    fontFamily: 'var(--font-sans)',
    fontSize: '17px',
    fontWeight: 700,
    letterSpacing: '0.08em',
    color: '#F1F5F9',
  },
  centerSection: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  passiveBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '7px',
    padding: '3px 12px',
    fontSize: '11px',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.04em',
    color: '#8A8D9B',
    backgroundColor: '#1C1C21',
    border: '1px solid #2B2C34',
    borderRadius: '2px',
  },
  passiveDot: {
    width: '4px',
    height: '4px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
  rightSection: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
  },
  statusPill: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '3px 10px',
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    letterSpacing: '0.04em',
    color: '#CBD5E1',
    backgroundColor: '#1C1C21',
    border: '1px solid #2B2C34',
    borderRadius: '12px',
  },
  statusDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
  },
};
