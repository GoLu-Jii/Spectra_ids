import React, { useState, useEffect } from 'react';
import { Search, ChevronRight, GitBranch, X } from 'lucide-react';
import useAppStore from '../../store/useAppStore';
import { ingestRepository, getIngestStatus } from '../../api/sherpaClient';

const STAGES = [
  '📥  Cloning repository...',
  '🔍  Running AST analysis...',
  '⚙️   Chunking & uploading to Chroma...',
  '🗺️   Building architecture graph...',
  '✅  Ready.',
];

const BOOT_LOGS = [
  "loading AST parser...",
  "connecting to ChromaDB...",
  "awaiting repository target...",
  "system telemetry online...",
];

const TARGET_TITLE = "CODE_Sherpa";
const CHAR_SET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@#$*!";

// Random 11-char string to prevent mounting flash layout shift
const INITIAL_SCRAMBLE = "X4!G_9$P#L@"; 

const FloatingCommandBar = () => {
  const [inputValue, setInputValue] = useState('');
  const [stageIndex, setStageIndex] = useState(0);
  const [minimised, setMinimised] = useState(false);
  const { repo, setRepoUrl, setRepoStatus, setRepoData } = useAppStore();

  const [isInputFocused, setIsInputFocused] = useState(false);
  const [scrambleText, setScrambleText] = useState(INITIAL_SCRAMBLE);
  const [bootIndex, setBootIndex] = useState(0);

  const statusToStageIndex = (status) => {
    switch (status) {
      case 'queued':
      case 'cloning':
        return 0;
      case 'analyzing':
        return 1;
      case 'ingesting':
        return 2;
      case 'charting':
        return 3;
      case 'complete':
        return STAGES.length - 1;
      default:
        return 0;
    }
  };

  // Cipher Scramble Effect
  useEffect(() => {
    let iteration = 0;
    const interval = setInterval(() => {
      setScrambleText(TARGET_TITLE.split("")
        .map((letter, index) => {
          if (index < iteration) {
            return TARGET_TITLE[index];
          }
          return CHAR_SET[Math.floor(Math.random() * CHAR_SET.length)];
        })
        .join("")
      );

      if (iteration >= TARGET_TITLE.length) {
        clearInterval(interval);
      }
      iteration += 1 / 3; // Step resolution speed
    }, 40);
    return () => clearInterval(interval);
  }, []);

  // Boot Log Cycle Effect
  useEffect(() => {
    const intv = setInterval(() => {
      setBootIndex((prev) => (prev + 1) % BOOT_LOGS.length);
    }, 2500);
    return () => clearInterval(intv);
  }, []);

  // Advance the fake terminal stages while waiting
  const startStageAnimation = () => {
    let idx = 0;
    const iv = setInterval(() => {
      idx = Math.min(idx + 1, STAGES.length - 2); // stay below "Ready" until done
      setStageIndex(idx);
    }, 7000);
    return () => clearInterval(iv);
  };

  const handleIngest = async (e) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setRepoUrl(inputValue.trim());
    setRepoStatus('loading');
    setStageIndex(0);

    const stopAnimation = startStageAnimation();
    let pollingInterval = null;

    const stopPolling = () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
      }
    };

    try {
      const queuedResponse = await ingestRepository(inputValue.trim());
      const jobId = queuedResponse?.job_id;
      if (!jobId) {
        throw new Error('No ingest job ID returned by backend.');
      }

      setStageIndex(statusToStageIndex(queuedResponse.status || 'queued'));

      const checkJob = async () => {
        try {
          const statusResponse = await getIngestStatus(jobId);
          setStageIndex(statusToStageIndex(statusResponse.status));

          if (statusResponse.status === 'complete') {
            stopPolling();
            stopAnimation();
            setRepoData(statusResponse);
            setTimeout(() => setMinimised(true), 1200);
          } else if (statusResponse.status === 'failed') {
            stopPolling();
            stopAnimation();
            setRepoStatus('error', statusResponse.message || 'Repository ingest failed.');
          }
        } catch (statusErr) {
          stopPolling();
          stopAnimation();
          console.error('Error polling ingest status:', statusErr);
          setRepoStatus('error', statusErr.message || 'Unable to retrieve ingest status.');
        }
      };

      await checkJob();
      pollingInterval = setInterval(checkJob, 3000);
    } catch (err) {
      stopPolling();
      stopAnimation();
      const errMsg =
        err?.response?.status === 403
          ? 'Access denied. Is the repository public?'
          : err?.response?.status === 404
          ? 'Repository not found. Check the URL.'
          : err?.code === 'ECONNABORTED'
          ? 'Request timed out — the repository may be too large.'
          : err?.message || 'Unknown error.';
      setRepoStatus('error', errMsg);
    }
  };

  // ---------------------------------------------------------------
  // MINIMISED PILL (after ingestion)
  // ---------------------------------------------------------------
  if (repo.status === 'ready' && minimised) {
    return (
      <div className="absolute top-4 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 px-4 py-2 font-[var(--font-jetbrains)] text-xs border border-[var(--color-telemetry-border)] bg-[var(--color-telemetry-bg)] shadow-md animate-float">
        <GitBranch size={12} className="text-[var(--color-telemetry-accent)]" />
        <span className="text-[var(--color-telemetry-muted)] max-w-[300px] truncate">{repo.url}</span>
        <span className="text-green-400 tracking-widest">STATUS:READY</span>
        <button
          onClick={() => setMinimised(false)}
          className="text-[var(--color-telemetry-muted)] hover:text-[var(--color-telemetry-text)] transition-colors"
        >
          <X size={12} />
        </button>
      </div>
    );
  }

  // ---------------------------------------------------------------
  // HIDDEN when ready but not minimised (user expanded it back)
  // ---------------------------------------------------------------

  return (
    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full flex flex-col items-center z-50 animate-float px-4">
      
      {/* Target Lock Identity */}
      <div className="mb-10 text-center font-[var(--font-jetbrains)] flex flex-col items-center select-none pointer-events-none">
        <div className="text-[var(--color-telemetry-muted)] text-[10px] md:text-xs tracking-[0.2em] mb-4 opacity-80">
          &lt;SYSTEM::INITIALIZE&gt;
        </div>
        <div className="text-4xl md:text-6xl lg:text-[5.5rem] font-medium tracking-tight text-white mb-4">
          {scrambleText}
          <span 
            className={`inline-block w-[0.55em] h-[0.9em] ml-2 align-baseline bg-[var(--color-telemetry-accent)] ${!isInputFocused ? 'animate-blink' : ''}`}
          ></span>
        </div>
        <div className="text-[var(--color-telemetry-muted)] text-xs md:text-sm h-4 transition-opacity duration-500 opacity-70">
           {'>'} {BOOT_LOGS[bootIndex]}
        </div>
      </div>

      {/* Terminal Command Bar */}
      <div className="w-full max-w-2xl">
        <div
          className="p-6 transition-all duration-500"
          style={{
            background: 'var(--color-telemetry-bg)',
            border: '1px solid var(--color-telemetry-border)',
            boxShadow: isInputFocused ? '0 0 50px rgba(255,123,75,0.06)' : 'none'
          }}
        >
          {/* Header label */}
          <div className="flex items-center gap-3 mb-5 font-[var(--font-jetbrains)] text-[10px] tracking-widest text-[var(--color-telemetry-muted)] uppercase">
            <GitBranch size={14} />
            ENTER GITHUB TARGET
          </div>

          {/* ---- LOADING STATE ---- */}
          {repo.status === 'loading' && (
            <div className="font-[var(--font-jetbrains)] text-sm flex flex-col gap-3">
              <div className="flex items-center gap-2 text-[var(--color-telemetry-text)]">
                <ChevronRight size={14} className="text-[var(--color-telemetry-accent)] flex-shrink-0" />
                <span className="text-[var(--color-telemetry-muted)] text-[11px] truncate">{repo.url}</span>
              </div>

              {STAGES.map((stage, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-2 transition-all duration-300 ${
                    i < stageIndex
                      ? 'opacity-40 line-through text-[var(--color-telemetry-muted)]'
                      : i === stageIndex
                      ? 'text-[var(--color-telemetry-text)]'
                      : 'opacity-20 text-[var(--color-telemetry-muted)]'
                  }`}
                >
                  <span>{stage}</span>
                  {i === stageIndex && i < STAGES.length - 1 && (
                    <span className="w-2 h-4 bg-[var(--color-telemetry-accent)] animate-blink inline-block flex-shrink-0" />
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ---- INPUT STATE ---- */}
          {repo.status !== 'loading' && (
            <form onSubmit={handleIngest} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search
                  size={16}
                  className={`absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none transition-colors duration-300 ${isInputFocused ? 'text-[var(--color-telemetry-accent)]' : 'text-[var(--color-telemetry-muted)]'}`}
                />
                <input
                  type="text"
                  value={inputValue}
                  onChange={e => setInputValue(e.target.value)}
                  placeholder="https://github.com/username/repository"
                  className={`w-full bg-transparent text-[var(--color-telemetry-text)] font-[var(--font-jetbrains)] text-sm px-11 py-3 placeholder-[var(--color-telemetry-muted)] outline-none transition-all duration-300 border ${isInputFocused ? 'border-[var(--color-telemetry-accent)] shadow-[0_0_15px_rgba(255,123,75,0.15)]' : 'border-[var(--color-telemetry-border)]'}`}
                  onFocus={() => setIsInputFocused(true)}
                  onBlur={() => setIsInputFocused(false)}
                />
              </div>
              <button
                type="submit"
                disabled={!inputValue.trim()}
                className="font-[var(--font-jetbrains)] text-[11px] uppercase tracking-widest px-8 flex items-center justify-center transition-all duration-300 disabled:opacity-30 disabled:cursor-not-allowed border border-[var(--color-telemetry-accent)] text-[var(--color-telemetry-accent)] bg-transparent hover:bg-[var(--color-telemetry-accent)] hover:text-[var(--color-telemetry-bg)] mt-3 sm:mt-0"
              >
                Ingest
              </button>
            </form>
          )}

          {/* Error message */}
          {repo.status === 'error' && (
            <div
              className="mt-4 pt-4 font-[var(--font-jetbrains)] text-[11px]"
              style={{
                borderTop: '1px solid var(--color-telemetry-border)',
                color: '#f87171',
              }}
            >
              ERR: {repo.error}
            </div>
          )}
        </div>

        {/* System Notice */}
        {repo.status !== 'ready' && (
          <div className="mt-8 flex flex-col items-center justify-center gap-2 pointer-events-none select-none">
            <div className="font-[var(--font-jetbrains)] text-[10px] md:text-xs text-[var(--color-telemetry-muted)] uppercase tracking-[0.15em] opacity-80 flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-telemetry-accent)] animate-pulse" />
              Code Sherpa v1 — Limited explicitly to Python language
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FloatingCommandBar;
