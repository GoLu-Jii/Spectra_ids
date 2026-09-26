import React, { useEffect, useRef } from 'react';

const CHAR_SET = '0123456789ABCDEFIP_TCP_UDP_SYN_ACK_0x45_0x00_@#$*!';

interface StreamRow {
  y: number;
  x: number;
  speed: number;
  length: number;
  chars: string[];
}

export const HorizontalPacketStream: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;

    const updateSize = () => {
      if (canvas.parentElement) {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
      }
    };

    updateSize();
    window.addEventListener('resize', updateSize);

    // Generate horizontal stream rows
    const rowHeight = 18;
    const numRows = Math.floor(canvas.height / rowHeight);
    const streams: StreamRow[] = [];

    const generateRow = (rowIndex: number): StreamRow => {
      const length = Math.floor(12 + Math.random() * 16);
      const chars: string[] = [];
      for (let i = 0; i < length; i++) {
        chars.push(CHAR_SET[Math.floor(Math.random() * CHAR_SET.length)]);
      }
      return {
        y: rowIndex * rowHeight + 14,
        x: Math.random() * (canvas.width || 400) - canvas.width,
        speed: 1.8 + Math.random() * 3.0,
        length,
        chars,
      };
    };

    for (let i = 0; i < numRows; i++) {
      streams.push(generateRow(i));
    }

    const render = () => {
      // Smooth fade background matching warm charcoal gray
      ctx.fillStyle = 'rgba(20, 20, 23, 0.42)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = '11px "JetBrains Mono", monospace';

      for (let i = 0; i < streams.length; i++) {
        const stream = streams[i];
        stream.x += stream.speed;

        // Reset stream when it crosses right boundary
        if (stream.x - stream.length * 12 > canvas.width) {
          streams[i] = generateRow(i);
          streams[i].x = -stream.length * 12;
        }

        // Randomly mutate trailing character for matrix jitter effect
        if (Math.random() < 0.06) {
          const mutateIdx = Math.floor(Math.random() * stream.chars.length);
          stream.chars[mutateIdx] = CHAR_SET[Math.floor(Math.random() * CHAR_SET.length)];
        }

        // Draw horizontal sequence of characters
        for (let j = 0; j < stream.chars.length; j++) {
          const charX = stream.x - j * 12;
          if (charX < 0 || charX > canvas.width) continue;

          if (j === 0) {
            // Head character: bright white pulse
            ctx.fillStyle = '#FFFFFF';
            ctx.shadowColor = 'rgba(255, 123, 75, 0.5)';
            ctx.shadowBlur = 4;
          } else if (j < 2) {
            // Leading trail: soft warm accent
            ctx.fillStyle = '#FF7B4B';
            ctx.shadowBlur = 0;
          } else {
            // Fading trail: muted slate gray
            const fade = Math.max(0.06, 1 - j / stream.length);
            ctx.fillStyle = `rgba(138, 141, 155, ${fade * 0.5})`;
            ctx.shadowBlur = 0;
          }

          ctx.fillText(stream.chars[j], charX, stream.y);
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', updateSize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div style={styles.wrapper}>
      <div style={styles.headerBar}>
        <div style={styles.titleGroup}>
          <span className="animate-pulse" style={styles.liveDot} />
          <span>PASSIVE TRAFFIC INGEST STREAM [LEFT ──► RIGHT]</span>
        </div>
        <span style={styles.statusTag}>MIRROR / SPAN</span>
      </div>

      <canvas ref={canvasRef} style={styles.canvas} />

      <div style={styles.footerOverlay}>
        <span style={styles.overlayText}>ONE-WAY INGEST BOUNDARY · PACKET STREAM ACTIVE</span>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    backgroundColor: '#141417',
    borderRight: '1px solid #2B2C34',
    position: 'relative',
    overflow: 'hidden',
    userSelect: 'none',
    fontFamily: 'var(--font-sans)',
  },
  headerBar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '7px 14px',
    borderBottom: '1px solid #2B2C34',
    backgroundColor: '#1C1C21',
    zIndex: 2,
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '11px',
    fontWeight: 600,
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.04em',
    color: '#F1F5F9',
  },
  liveDot: {
    width: '5px',
    height: '5px',
    borderRadius: '50%',
    backgroundColor: '#FF7B4B',
  },
  statusTag: {
    fontSize: '10px',
    fontWeight: 500,
    fontFamily: 'var(--font-sans)',
    color: '#CBD5E1',
    backgroundColor: 'rgba(43, 44, 52, 0.6)',
    border: '1px solid #383944',
    padding: '1px 6px',
    borderRadius: '1px',
  },
  canvas: {
    flexGrow: 1,
    width: '100%',
    height: '100%',
    display: 'block',
    backgroundColor: '#141417',
  },
  footerOverlay: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    padding: '5px 14px',
    backgroundColor: 'rgba(20, 20, 23, 0.88)',
    borderTop: '1px solid #2B2C34',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 2,
  },
  overlayText: {
    fontSize: '9px',
    fontFamily: 'var(--font-sans)',
    color: '#8A8D9B',
    letterSpacing: '0.06em',
    textTransform: 'uppercase',
  },
};
