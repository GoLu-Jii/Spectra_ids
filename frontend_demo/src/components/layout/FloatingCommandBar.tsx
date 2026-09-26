import React, { useState } from 'react';
import { useSpectra } from '../../context/SpectraContext';
import { ForensicLineageModal } from './ForensicLineageModal';

export const FloatingCommandBar: React.FC = () => {
  const { resetCounters, threatAggregates } = useSpectra();
  const [isMinimized, setIsMinimized] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [mode, setMode] = useState<'LIVE SPAN/TAP' | 'REPLAY PCAP'>('LIVE SPAN/TAP');
  const [selectedPcap, setSelectedPcap] = useState<string>('pcap_ddos_syn_burst.pcap');
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const handleExportAllJson = () => {
    const jsonString = JSON.stringify(threatAggregates, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SPECTRA_FULL_MATRIX_EVIDENCE_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isMinimized) {
    return (
      <div style={styles.minimizedPill} onClick={() => setIsMinimized(false)}>
        <span className="animate-pulse" style={styles.dot} />
        <span style={styles.miniText}>SPECtRA OPERATOR DOCK</span>
        <span style={styles.miniTag}>{mode}</span>
      </div>
    );
  }

  return (
    <>
      <div style={styles.floatingContainer}>
        {/* Brand & Ingest Mode Selector */}
        <div style={styles.leftSection}>
          <div style={styles.logoBadge}>
            <span className="animate-pulse" style={styles.dot} />
            <span>SPECtRA</span>
          </div>

          <div style={styles.modeToggleGroup}>
            <button
              onClick={() => setMode('LIVE SPAN/TAP')}
              style={{
                ...styles.modeBtn,
                ...(mode === 'LIVE SPAN/TAP' ? styles.modeBtnActive : {}),
              }}
            >
              LIVE SPAN/TAP
            </button>
            <button
              onClick={() => setMode('REPLAY PCAP')}
              style={{
                ...styles.modeBtn,
                ...(mode === 'REPLAY PCAP' ? styles.modeBtnActive : {}),
              }}
            >
              REPLAY PCAP
            </button>
          </div>

          {/* PCAP Scenario Selector Dropdown when in REPLAY mode */}
          {mode === 'REPLAY PCAP' && (
            <select
              value={selectedPcap}
              onChange={(e) => setSelectedPcap(e.target.value)}
              style={styles.pcapSelect}
            >
              <option value="pcap_ddos_syn_burst.pcap">ddos_syn_burst.pcap</option>
              <option value="pcap_c2_beaconing.pcap">c2_beaconing_jitter.pcap</option>
              <option value="pcap_dns_tunneling.pcap">dns_tunnel_dga.pcap</option>
              <option value="pcap_exfiltration.pcap">data_exfiltration.pcap</option>
            </select>
          )}
        </div>

        <div style={styles.divider} />

        {/* Quick Action Controls & USP Audit Trigger */}
        <div style={styles.rightSection}>
          {/* USP Trigger Button */}
          <button onClick={() => setIsModalOpen(true)} style={styles.uspBtn}>
            🔬 FORENSIC LINEAGE & AUDIT
          </button>

          <button
            onClick={() => setIsPaused(!isPaused)}
            style={{
              ...styles.actionBtn,
              ...(isPaused ? styles.actionBtnDanger : {}),
            }}
          >
            {isPaused ? '▶ RESUME STREAM' : '⏸ PAUSE INGEST'}
          </button>

          <button onClick={handleExportAllJson} style={styles.actionBtn}>
            ⤓ EXPORT MATRIX JSON
          </button>

          <button onClick={resetCounters} style={styles.actionBtn}>
            ↺ RESET COUNTERS
          </button>

          <button onClick={() => setIsMinimized(true)} style={styles.minimizeBtn} title="Minimize Command Bar">
            ✕
          </button>
        </div>
      </div>

      {/* Forensic Lineage & Latency Audit Modal */}
      <ForensicLineageModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </>
  );
};

const styles: Record<string, React.CSSProperties> = {
  floatingContainer: {
    position: 'fixed',
    bottom: '16px',
    left: '50%',
    transform: 'translateX(-50%)',
    zIndex: 50,
    display: 'flex',
    alignItems: 'center',
    gap: '14px',
    padding: '8px 16px',
    backgroundColor: 'rgba(28, 28, 33, 0.94)',
    backdropFilter: 'blur(12px)',
    border: '1px solid rgba(255, 123, 75, 0.4)',
    borderRadius: '24px',
    boxShadow: '0 10px 30px rgba(0, 0, 0, 0.6), 0 0 20px rgba(255, 123, 75, 0.2)',
    userSelect: 'none',
    transition: 'all 200ms ease',
  },
  minimizedPill: {
    position: 'fixed',
    bottom: '16px',
    left: '50%',
    transform: 'translateX(-50%)',
    zIndex: 50,
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '6px 14px',
    backgroundColor: 'rgba(28, 28, 33, 0.94)',
    backdropFilter: 'blur(12px)',
    border: '1px solid #FF7B4B',
    borderRadius: '16px',
    boxShadow: '0 4px 15px rgba(0, 0, 0, 0.5), 0 0 10px rgba(255, 123, 75, 0.3)',
    cursor: 'pointer',
    userSelect: 'none',
  },
  dot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
  miniText: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    fontWeight: 700,
    color: '#F1F5F9',
    letterSpacing: '0.04em',
  },
  miniTag: {
    fontFamily: 'var(--font-mono)',
    fontSize: '10px',
    color: '#FF7B4B',
  },
  leftSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  logoBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    fontFamily: 'var(--font-sans)',
    fontSize: '12px',
    fontWeight: 800,
    color: '#F1F5F9',
    letterSpacing: '0.06em',
  },
  modeToggleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '2px',
    backgroundColor: '#141417',
    padding: '2px',
    borderRadius: '12px',
    border: '1px solid #2B2C34',
  },
  modeBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '10px',
    fontWeight: 700,
    padding: '3px 8px',
    borderRadius: '10px',
    color: '#8A8D9B',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 150ms ease',
  },
  modeBtnActive: {
    color: '#FFFFFF',
    backgroundColor: '#FF7B4B',
  },
  pcapSelect: {
    fontFamily: 'var(--font-mono)',
    fontSize: '10px',
    color: '#FF7B4B',
    backgroundColor: '#141417',
    border: '1px solid #FF7B4B',
    borderRadius: '8px',
    padding: '2px 6px',
    outline: 'none',
  },
  divider: {
    width: '1px',
    height: '18px',
    backgroundColor: '#2B2C34',
  },
  rightSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  uspBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '10px',
    fontWeight: 700,
    color: '#FF7B4B',
    backgroundColor: 'rgba(255, 123, 75, 0.12)',
    border: '1px solid #FF7B4B',
    padding: '4px 10px',
    borderRadius: '12px',
    cursor: 'pointer',
    transition: 'all 150ms ease',
  },
  actionBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '10px',
    fontWeight: 700,
    color: '#CBD5E1',
    backgroundColor: 'rgba(43, 44, 52, 0.6)',
    border: '1px solid #383944',
    padding: '4px 10px',
    borderRadius: '12px',
    cursor: 'pointer',
    transition: 'all 150ms ease',
  },
  actionBtnDanger: {
    color: '#FF7B4B',
    backgroundColor: 'rgba(255, 123, 75, 0.15)',
    borderColor: '#FF7B4B',
  },
  minimizeBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    color: '#8A8D9B',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '2px 6px',
  },
};
