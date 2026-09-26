import React, { useState, useEffect } from 'react';
import { useSpectra } from '../../context/SpectraContext';

export const ThreatTrendChart: React.FC = () => {
  const { metrics } = useSpectra();
  const [timeRange, setTimeRange] = useState<'LIVE' | '10M' | '1H' | '24H'>('LIVE');
  const [dataPoints, setDataPoints] = useState<number[]>([
    24, 38, 45, 32, 68, 92, 74, 55, 62, 78, 85, 94
  ]);

  // Continuously update trend wave with live packet rate metric
  useEffect(() => {
    const interval = setInterval(() => {
      const ppsNormalized = Math.min(100, Math.max(15, (metrics.packetsPerSec / 25000) * 100));
      setDataPoints((prev) => [...prev.slice(1), ppsNormalized]);
    }, 1200);
    return () => clearInterval(interval);
  }, [metrics.packetsPerSec]);

  // Construct SVG Bézier Smooth Curve
  const width = 500;
  const height = 140;

  const points = dataPoints.map((val, idx) => {
    const x = (idx / (dataPoints.length - 1)) * width;
    const y = height - (val / 100) * (height - 20) - 10;
    return { x, y, val };
  });

  // Create smooth cubic bézier curve string
  let pathD = `M ${points[0].x},${points[0].y}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i];
    const p1 = points[i + 1];
    const cp1x = p0.x + (p1.x - p0.x) / 2;
    const cp1y = p0.y;
    const cp2x = p0.x + (p1.x - p0.x) / 2;
    const cp2y = p1.y;
    pathD += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p1.x},${p1.y}`;
  }

  const areaD = `${pathD} L ${width},${height} L 0,${height} Z`;

  // Focus node (peak point, like reference $74,12K point)
  const peakIndex = points.reduce((maxIdx, p, idx, arr) => (p.val > arr[maxIdx].val ? idx : maxIdx), 0);
  const peakPoint = points[peakIndex] || points[points.length - 1];

  return (
    <div style={styles.cardContainer}>
      {/* Header with Title and Time Pills */}
      <div style={styles.headerRow}>
        <div>
          <div style={styles.cardTitle}>Flow Velocity & Threat Trend</div>
          <div style={styles.cardSubTitle}>Real-time packet ingress vs detector response window</div>
        </div>

        <div style={styles.pillGroup}>
          {(['LIVE', '10M', '1H', '24H'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setTimeRange(mode)}
              style={{
                ...styles.pillBtn,
                ...(timeRange === mode ? styles.pillBtnActive : {}),
              }}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Main Chart Area */}
      <div style={styles.chartWrapper}>
        {/* Y Axis Grid Lines */}
        <div style={styles.yAxisLabels}>
          <span>100K</span>
          <span>50K</span>
          <span>0</span>
        </div>

        <div style={styles.svgContainer}>
          <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
            <defs>
              <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#FF7B4B" stopOpacity={0.35} />
                <stop offset="60%" stopColor="#FF7B4B" stopOpacity={0.08} />
                <stop offset="100%" stopColor="#FF7B4B" stopOpacity={0.0} />
              </linearGradient>

              <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#FF8C5F" />
                <stop offset="50%" stopColor="#FF7B4B" />
                <stop offset="100%" stopColor="#FF5E36" />
              </linearGradient>
            </defs>

            {/* Grid Horizontal Lines */}
            <line x1="0" y1="10" x2={width} y2="10" stroke="#2B2C34" strokeDasharray="3 3" />
            <line x1="0" y1={height / 2} x2={width} y2={height / 2} stroke="#2B2C34" strokeDasharray="3 3" />
            <line x1="0" y1={height - 10} x2={width} y2={height - 10} stroke="#2B2C34" />

            {/* Gradient Area Fill */}
            <path d={areaD} fill="url(#areaGradient)" />

            {/* Main Smooth Curve */}
            <path d={pathD} fill="none" stroke="url(#lineGradient)" strokeWidth="2.5" strokeLinecap="round" />

            {/* Glowing Peak Data Point Node */}
            <g transform={`translate(${peakPoint.x}, ${peakPoint.y})`}>
              <circle r="7" fill="rgba(255, 123, 75, 0.25)" className="animate-pulse" />
              <circle r="4" fill="#FFFFFF" stroke="#FF7B4B" strokeWidth="2" />
            </g>
          </svg>

          {/* Floating Data Badge Callout */}
          <div
            style={{
              ...styles.floatingTooltip,
              left: `${(peakPoint.x / width) * 100}%`,
              top: `${Math.max(10, (peakPoint.y / height) * 100 - 32)}%`,
            }}
          >
            <span style={styles.tooltipVal}>{(metrics.packetsPerSec / 1000).toFixed(1)}K pps</span>
            <span style={styles.tooltipBadge}>▲ +13%</span>
          </div>
        </div>
      </div>

      {/* X Axis Time Labels */}
      <div style={styles.xAxisRow}>
        <span>T-12s</span>
        <span>T-10s</span>
        <span>T-8s</span>
        <span>T-6s</span>
        <span>T-4s</span>
        <span>T-2s</span>
        <span>NOW</span>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  cardContainer: {
    backgroundColor: '#1C1C21',
    border: '1px solid #2B2C34',
    borderRadius: '4px',
    padding: '14px 16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
    margin: '10px 14px',
    userSelect: 'none',
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  cardTitle: {
    fontFamily: 'var(--font-sans)',
    fontSize: '13px',
    fontWeight: 700,
    color: '#F1F5F9',
    letterSpacing: '0.02em',
  },
  cardSubTitle: {
    fontFamily: 'var(--font-sans)',
    fontSize: '11px',
    color: '#8A8D9B',
  },
  pillGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    backgroundColor: '#141417',
    padding: '3px',
    borderRadius: '14px',
    border: '1px solid #2B2C34',
  },
  pillBtn: {
    fontFamily: 'var(--font-sans)',
    fontSize: '10px',
    fontWeight: 600,
    padding: '3px 10px',
    borderRadius: '12px',
    color: '#8A8D9B',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 150ms ease',
  },
  pillBtnActive: {
    color: '#FFFFFF',
    backgroundColor: '#FF7B4B',
    boxShadow: '0 0 10px rgba(255, 123, 75, 0.4)',
  },
  chartWrapper: {
    display: 'flex',
    alignItems: 'stretch',
    gap: '8px',
    height: '140px',
    position: 'relative',
  },
  yAxisLabels: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    fontSize: '9px',
    fontFamily: 'var(--font-mono)',
    color: '#5A5D6B',
    paddingBottom: '6px',
  },
  svgContainer: {
    flexGrow: 1,
    height: '100%',
    position: 'relative',
  },
  floatingTooltip: {
    position: 'absolute',
    transform: 'translate(-50%, -100%)',
    backgroundColor: 'rgba(28, 28, 33, 0.95)',
    border: '1px solid #FF7B4B',
    borderRadius: '4px',
    padding: '3px 8px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    boxShadow: '0 4px 14px rgba(0, 0, 0, 0.5), 0 0 10px rgba(255, 123, 75, 0.2)',
    pointerEvents: 'none',
    whiteSpace: 'nowrap',
    zIndex: 10,
  },
  tooltipVal: {
    fontFamily: 'var(--font-mono)',
    fontSize: '11px',
    fontWeight: 600,
    color: '#F1F5F9',
  },
  tooltipBadge: {
    fontFamily: 'var(--font-sans)',
    fontSize: '10px',
    fontWeight: 700,
    color: '#FF7B4B',
  },
  xAxisRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '9px',
    fontFamily: 'var(--font-mono)',
    color: '#5A5D6B',
    paddingLeft: '24px',
  },
};
