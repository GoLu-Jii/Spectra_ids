import React, { useState, useEffect, useRef } from 'react';
import { Header } from './Header';
import { MetricStrip } from './MetricStrip';
import { PipelineBar } from './PipelineBar';
import { HorizontalPacketStream } from '../telemetry/HorizontalPacketStream';
import { ThreatTrendChart } from '../telemetry/ThreatTrendChart';
import { ThreatMatrixTable } from '../alerts/ThreatMatrixTable';
import { FloatingCommandBar } from './FloatingCommandBar';

export const DashboardShell: React.FC = () => {
  const [leftWidthPercent, setLeftWidthPercent] = useState<number>(25);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const workspaceRef = useRef<HTMLDivElement | null>(null);

  const startDragging = (e: React.MouseEvent | React.TouchEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  useEffect(() => {
    const handleMove = (clientX: number) => {
      if (!isDragging || !workspaceRef.current) return;
      const rect = workspaceRef.current.getBoundingClientRect();
      const offsetX = clientX - rect.left;
      const percent = (offsetX / rect.width) * 100;
      // Clamp split ratio between 15% and 75%
      const clamped = Math.max(15, Math.min(75, percent));
      setLeftWidthPercent(clamped);
    };

    const handleMouseMove = (e: MouseEvent) => {
      handleMove(e.clientX);
    };

    const handleTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        handleMove(e.touches[0].clientX);
      }
    };

    const stopDragging = () => {
      if (isDragging) {
        setIsDragging(false);
      }
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', stopDragging);
      window.addEventListener('touchmove', handleTouchMove);
      window.addEventListener('touchend', stopDragging);
    }

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', stopDragging);
      window.removeEventListener('touchmove', handleTouchMove);
      window.removeEventListener('touchend', stopDragging);
    };
  }, [isDragging]);

  return (
    <div style={styles.shell}>
      {/* Top Header Bar */}
      <Header />

      {/* Operational Telemetry Strip */}
      <MetricStrip />

      {/* Main Resizable Workspace Split */}
      <div ref={workspaceRef} style={styles.mainWorkspace}>
        {/* Left Section (0 to 4 ratio): Packet Stream Canvas + Bézier Trend Chart */}
        <div
          style={{
            ...styles.leftStreamContainer,
            width: `${leftWidthPercent}%`,
            flex: `0 0 ${leftWidthPercent}%`,
          }}
        >
          {/* Top: Packet Ingest Animation */}
          <div style={styles.packetStreamBox}>
            <HorizontalPacketStream />
          </div>

          {/* Bottom: Smooth Wave Trend Chart */}
          <div style={styles.trendChartBox}>
            <ThreatTrendChart />
          </div>
        </div>

        {/* Interactive Resizable Divider Bar */}
        <div
          style={{
            ...styles.dividerHandle,
            backgroundColor: isDragging ? '#FF7B4B' : '#2B2C34',
          }}
          onMouseDown={startDragging}
          onTouchStart={startDragging}
          title="Drag to resize panel ratio"
        >
          <div style={styles.dividerGrip} />
        </div>

        {/* Right Section (4 to 10 ratio): Threat Family Detection Table */}
        <div
          style={{
            ...styles.rightDashboardContainer,
            width: `${100 - leftWidthPercent}%`,
            flex: `1 1 ${100 - leftWidthPercent}%`,
          }}
        >
          <ThreatMatrixTable />
        </div>
      </div>

      {/* Pipeline Status Footer Bar */}
      <PipelineBar />

      {/* Floating Bottom Command Dock */}
      <FloatingCommandBar />
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  shell: {
    height: '100vh',
    maxHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#141417',
    color: '#FFFFFF',
    overflow: 'hidden',
    position: 'relative',
  },
  mainWorkspace: {
    flexGrow: 1,
    display: 'flex',
    flexDirection: 'row',
    overflow: 'hidden',
    backgroundColor: '#141417',
    position: 'relative',
  },
  leftStreamContainer: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    borderRight: '1px solid #2B2C34',
  },
  packetStreamBox: {
    flex: '1 1 50%',
    minHeight: '200px',
    position: 'relative',
    overflow: 'hidden',
  },
  trendChartBox: {
    flex: '1 1 50%',
    overflow: 'hidden',
    backgroundColor: '#141417',
  },
  dividerHandle: {
    width: '6px',
    height: '100%',
    cursor: 'col-resize',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10,
    userSelect: 'none',
    transition: 'background-color 150ms ease',
  },
  dividerGrip: {
    width: '2px',
    height: '24px',
    backgroundColor: 'rgba(255, 255, 255, 0.3)',
    borderRadius: '1px',
  },
  rightDashboardContainer: {
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
};
