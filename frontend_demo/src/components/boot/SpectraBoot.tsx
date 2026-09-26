import React, { useState, useEffect } from 'react';

interface SpectraBootProps {
  onComplete?: () => void;
}

const STAGES = [
  'initializing capture interface...',
  'connecting to telemetry stream...',
  'initializing detection engine...',
  'SYSTEM READY',
];

const BOOT_LOGS = [
  'initializing capture interface...',
  'connecting to telemetry stream...',
  'initializing detection engine...',
  'system telemetry online...',
];

const TARGET_TITLE = 'SPECtRA';
const CHAR_SET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@#$*!';
const INITIAL_SCRAMBLE = 'X4!g_9$';

export const SpectraBoot: React.FC<SpectraBootProps> = ({ onComplete }) => {
  const [stageIndex, setStageIndex] = useState(0);
  const [scrambleText, setScrambleText] = useState(INITIAL_SCRAMBLE);
  const [boxVisible, setBoxVisible] = useState(false);
  const [bootIndex, setBootIndex] = useState(0);

  // 1. SPECtRA Cipher Scramble Effect (Starts at t = 0s)
  useEffect(() => {
    let iteration = 0;
    const interval = setInterval(() => {
      setScrambleText(
        TARGET_TITLE.split('')
          .map((_, index) => {
            if (index < iteration) {
              return TARGET_TITLE[index];
            }
            return CHAR_SET[Math.floor(Math.random() * CHAR_SET.length)];
          })
          .join('')
      );

      if (iteration >= TARGET_TITLE.length) {
        clearInterval(interval);
      }
      iteration += 1 / 3;
    }, 50);

    return () => clearInterval(interval);
  }, []);

  // 2. Boot Log Cycle Effect
  useEffect(() => {
    const intv = setInterval(() => {
      setBootIndex((prev) => (prev + 1) % BOOT_LOGS.length);
    }, 2200);
    return () => clearInterval(intv);
  }, []);

  // 3. Reveal the terminal sequence box exactly at t = 1.0s
  useEffect(() => {
    const timer = setTimeout(() => {
      setBoxVisible(true);
    }, 1000);
    return () => clearTimeout(timer);
  }, []);

  // 4. Stage Progress Advancement (Starts once sequence box appears at t = 1.0s)
  useEffect(() => {
    if (!boxVisible) return;

    let idx = 0;
    const interval = setInterval(() => {
      idx += 1;
      if (idx < STAGES.length) {
        setStageIndex(idx);
        if (idx === STAGES.length - 1) {
          clearInterval(interval);
          setTimeout(() => {
            if (onComplete) onComplete();
          }, 1000);
        }
      }
    }, 700);

    return () => clearInterval(interval);
  }, [boxVisible, onComplete]);

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'var(--color-telemetry-bg)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '1.5rem',
        userSelect: 'none',
        overflow: 'hidden',
      }}
    >
      <div
        className="animate-float"
        style={{
          width: '100%',
          maxWidth: '42rem',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          transition: 'all 800ms cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Target Lock Identity */}
        <div
          style={{
            marginBottom: boxVisible ? '2.5rem' : '0rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            pointerEvents: 'none',
            transition: 'all 800ms cubic-bezier(0.16, 1, 0.3, 1)',
            transform: boxVisible ? 'translateY(0)' : 'translateY(24px)',
          }}
        >
          <div
            style={{
              fontFamily: 'var(--font-jetbrains)',
              color: 'var(--color-telemetry-muted)',
              fontSize: '11px',
              letterSpacing: '0.2em',
              marginBottom: '1rem',
              opacity: 0.8,
              textTransform: 'uppercase',
            }}
          >
            &lt;SYSTEM::INITIALIZE&gt;
          </div>

          {/* SPECtRA Title with Proportional Inter font for organic character width jitter */}
          <div
            style={{
              fontFamily: "var(--font-inter), 'Inter', system-ui, -apple-system, sans-serif",
              fontSize: '5.25rem',
              fontWeight: 500,
              letterSpacing: '-0.025em',
              color: 'var(--color-telemetry-text)',
              marginBottom: '1rem',
              display: 'inline-flex',
              alignItems: 'baseline',
              justifyContent: 'center',
              lineHeight: 1,
            }}
          >
            <span>{scrambleText}</span>
            <span
              className="animate-blink"
              style={{
                display: 'inline-block',
                width: '0.55em',
                height: '0.9em',
                marginLeft: '0.5rem',
                verticalAlign: 'baseline',
                backgroundColor: 'var(--color-telemetry-accent)',
              }}
            />
          </div>

          <div
            style={{
              fontFamily: 'var(--font-jetbrains)',
              color: 'var(--color-telemetry-muted)',
              fontSize: '13px',
              letterSpacing: '0.04em',
              height: '1rem',
              transition: 'opacity 500ms',
              opacity: 0.7,
            }}
          >
            {'>'} {BOOT_LOGS[bootIndex]}
          </div>
        </div>

        {/* Terminal Command Bar (Appears smoothly at t = 1.0s) */}
        <div
          style={{
            width: '100%',
            opacity: boxVisible ? 1 : 0,
            transform: boxVisible ? 'translateY(0)' : 'translateY(30px)',
            transition: 'opacity 700ms cubic-bezier(0.16, 1, 0.3, 1), transform 700ms cubic-bezier(0.16, 1, 0.3, 1)',
            pointerEvents: boxVisible ? 'auto' : 'none',
          }}
        >
          <div
            style={{
              padding: '1.5rem',
              transition: 'all 500ms',
              background: 'var(--color-telemetry-bg)',
              border: '1px solid var(--color-telemetry-border)',
            }}
          >
            {/* Header label */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                marginBottom: '1.25rem',
                fontFamily: 'var(--font-jetbrains)',
                fontSize: '10px',
                letterSpacing: '0.1em',
                color: 'var(--color-telemetry-muted)',
                textTransform: 'uppercase',
              }}
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="4 17 10 11 4 5" />
                <line x1="12" y1="19" x2="20" y2="19" />
              </svg>
              SYSTEM INITIALIZATION SEQUENCE
            </div>

            {/* Stages Loading State */}
            <div
              style={{
                fontFamily: 'var(--font-jetbrains)',
                fontSize: '14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  color: 'var(--color-telemetry-text)',
                }}
              >
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  style={{ color: 'var(--color-telemetry-accent)', flexShrink: 0 }}
                >
                  <polyline points="9 18 15 12 9 6" />
                </svg>
                <span
                  style={{
                    color: 'var(--color-telemetry-muted)',
                    fontSize: '11px',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  spectra://localhost/engine
                </span>
              </div>

              {STAGES.map((stage, i) => {
                const isPassed = i < stageIndex;
                const isCurrent = i === stageIndex;

                return (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      transition: 'all 300ms',
                      opacity: isPassed ? 0.4 : isCurrent ? 1 : 0.2,
                      textDecoration: isPassed ? 'line-through' : 'none',
                      color: isPassed
                        ? 'var(--color-telemetry-muted)'
                        : isCurrent
                        ? 'var(--color-telemetry-text)'
                        : 'var(--color-telemetry-muted)',
                    }}
                  >
                    <span>{stage}</span>
                    {isCurrent && i < STAGES.length - 1 && (
                      <span
                        className="animate-blink"
                        style={{
                          width: '0.5rem',
                          height: '1rem',
                          backgroundColor: 'var(--color-telemetry-accent)',
                          display: 'inline-block',
                          flexShrink: 0,
                        }}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* System Notice */}
          <div
            style={{
              marginTop: '2rem',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              pointerEvents: 'none',
              userSelect: 'none',
            }}
          >
            <div
              style={{
                fontFamily: 'var(--font-jetbrains)',
                fontSize: '10px',
                color: 'var(--color-telemetry-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.15em',
                opacity: 0.8,
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <div
                className="animate-pulse"
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--color-telemetry-accent)',
                }}
              />
              SPECTRA v1.0 — REAL-TIME TELEMETRY & INTRUSION DETECTION SYSTEM
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SpectraBoot;
