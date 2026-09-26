import React from 'react';
import { useSpectra } from '../../context/SpectraContext';

export const PipelineBar: React.FC = () => {
  const { pipelineHealth } = useSpectra();

  return (
    <footer style={styles.footer}>
      {/* Pipeline Stage Indicators */}
      <div style={styles.stagesGroup}>
        <span style={styles.groupLabel}>PIPELINE STAGES:</span>
        {pipelineHealth.stages.map((stage, idx) => (
          <React.Fragment key={stage.id}>
            {idx > 0 && <span style={styles.divider}>│</span>}
            <div style={styles.stageTag}>
              <span style={styles.stageDot} />
              <span style={styles.stageName}>{stage.name}</span>
              <span style={styles.stageStatus}>[{stage.status}]</span>
            </div>
          </React.Fragment>
        ))}
      </div>

      {/* Health Metrics & Loss Budget */}
      <div style={styles.metricsGroup}>
        <div style={styles.statItem}>
          <span style={styles.statLabel}>PROCESSED:</span>
          <span style={styles.statValue}>{pipelineHealth.processedRecordsTotal.toLocaleString()}</span>
        </div>
        <span style={styles.divider}>│</span>
        <div style={styles.statItem}>
          <span style={styles.statLabel}>CAPTURE LOSS:</span>
          <span style={styles.statValue}>{pipelineHealth.lossRatePct.toFixed(2)}%</span>
        </div>
        <span style={styles.divider}>│</span>
        <div style={styles.streamBadge}>
          <span className="animate-pulse" style={styles.streamDot} />
          <span>{pipelineHealth.telemetryState}</span>
        </div>
      </div>
    </footer>
  );
};

const styles: Record<string, React.CSSProperties> = {
  footer: {
    height: '34px',
    backgroundColor: '#141417',
    borderTop: '1px solid #2B2C34',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 20px',
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    userSelect: 'none',
  },
  stagesGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '9px',
  },
  groupLabel: {
    color: '#8A8D9B',
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.04em',
  },
  stageTag: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  stageDot: {
    width: '4px',
    height: '4px',
    borderRadius: '50%',
    backgroundColor: '#5A5D6B',
  },
  stageName: {
    color: '#CBD5E1',
    fontWeight: 500,
    fontFamily: 'var(--font-sans)',
  },
  stageStatus: {
    color: '#8A8D9B',
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
  },
  divider: {
    color: '#2B2C34',
    fontSize: '10px',
  },
  metricsGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  statItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
  statLabel: {
    color: '#8A8D9B',
    fontSize: '10px',
    fontFamily: 'var(--font-sans)',
  },
  statValue: {
    color: '#E2E8F0',
    fontWeight: 500,
    fontFamily: 'var(--font-mono)',
  },
  streamBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    color: '#CBD5E1',
    fontWeight: 500,
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.04em',
  },
  streamDot: {
    width: '5px',
    height: '5px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
};
