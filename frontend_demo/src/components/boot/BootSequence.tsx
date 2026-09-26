import React, { useEffect, useState } from 'react';

interface BootSequenceProps {
  onComplete: () => void;
}

const BOOT_STEPS = [
  'Initializing monitoring environment...',
  'Loading configuration...',
  'Initializing capture interface...',
  'Connecting to telemetry stream...',
  'Initializing detection engine...',
  'SYSTEM READY',
];

export const BootSequence: React.FC<BootSequenceProps> = ({ onComplete }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev < BOOT_STEPS.length - 1) {
          setCompletedSteps((completed) => [...completed, prev]);
          return prev + 1;
        } else {
          clearInterval(timer);
          setTimeout(() => {
            onComplete();
          }, 700);
          return prev;
        }
      });
    }, 750);

    return () => clearInterval(timer);
  }, [onComplete]);

  const progressPct = Math.round(((completedSteps.length + 1) / BOOT_STEPS.length) * 100);

  return (
    <div style={styles.overlay}>
      <div style={styles.container}>
        {/* Header Header Brand */}
        <div style={styles.brandRow}>
          <div style={styles.logoBadge}>
            <span style={styles.logoDot} />
            <span style={styles.logoText}>SPECTRA</span>
          </div>
          <span style={styles.subText}>OPERATIONAL MONITORING ENGINE</span>
        </div>

        {/* Status Window */}
        <div style={styles.statusBox}>
          <div style={styles.stepList}>
            {BOOT_STEPS.map((step, idx) => {
              const isCurrent = idx === currentStepIndex;
              const isDone = completedSteps.includes(idx) || (idx === BOOT_STEPS.length - 1 && currentStepIndex === BOOT_STEPS.length - 1);
              const isPending = idx > currentStepIndex;

              return (
                <div key={idx} style={{
                  ...styles.stepItem,
                  opacity: isPending ? 0.35 : 1,
                  color: isDone ? '#38BDF8' : isCurrent ? '#00E5FF' : '#94A3B8',
                }}>
                  <span style={styles.stepPrefix}>
                    {isDone ? '[OK]' : isCurrent ? '[RUNNING]' : '[WAIT]'}
                  </span>
                  <span style={styles.stepText}>{step}</span>
                </div>
              );
            })}
          </div>

          {/* Progress Bar */}
          <div style={styles.progressTrack}>
            <div style={{ ...styles.progressBar, width: `${progressPct}%` }} />
          </div>

          <div style={styles.metaRow}>
            <span style={styles.metaText}>SECURITY BOUNDARY: PASSIVE / ONE-WAY</span>
            <span style={styles.metaText}>{progressPct}%</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: '#090B0E',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    fontFamily: 'var(--font-sans)',
  },
  container: {
    width: '540px',
    maxWidth: '90%',
    padding: '32px',
    backgroundColor: '#0E121A',
    border: '1px solid #1F283A',
    boxShadow: '0 12px 32px rgba(0,0,0,0.5)',
  },
  brandRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '24px',
    paddingBottom: '16px',
    borderBottom: '1px solid #19202E',
  },
  logoBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  logoDot: {
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    backgroundColor: '#00E5FF',
    boxShadow: '0 0 8px #00E5FF',
  },
  logoText: {
    fontFamily: 'var(--font-mono)',
    fontSize: '20px',
    fontWeight: 700,
    letterSpacing: '0.1em',
    color: '#F8FAFC',
  },
  subText: {
    fontFamily: 'var(--font-mono)',
    fontSize: '10px',
    color: '#64748B',
    letterSpacing: '0.08em',
  },
  statusBox: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  },
  stepList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
    minHeight: '180px',
  },
  stepItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    transition: 'color 0.2s ease, opacity 0.2s ease',
  },
  stepPrefix: {
    fontWeight: 600,
    width: '76px',
    flexShrink: 0,
  },
  stepText: {
    flexGrow: 1,
  },
  progressTrack: {
    height: '3px',
    backgroundColor: '#19202E',
    overflow: 'hidden',
    position: 'relative',
    marginTop: '8px',
  },
  progressBar: {
    height: '100%',
    backgroundColor: '#00E5FF',
    boxShadow: '0 0 6px #00E5FF',
    transition: 'width 0.3s ease',
  },
  metaRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontFamily: 'var(--font-mono)',
    fontSize: '10px',
    color: '#64748B',
    letterSpacing: '0.05em',
  },
};
