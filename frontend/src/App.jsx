import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, ChevronRight, CircleDot, Radio, RefreshCw, Server, Wifi, WifiOff, X } from 'lucide-react'

const LATENCY_METRICS = [
  'capture_to_alert',
  'capture_to_dashboard',
  'zeek_to_ingest',
  'queue_wait',
  'window_wait',
  'feature_time',
  'inference_time',
  'alert_generation_time',
  'delivery_time',
]
const MAX_RECONNECT_ATTEMPTS = 5

export function mergeAlerts(current, incoming) {
  const byId = new Map(current.map((alert) => [alert.alert_id, alert]))
  for (const alert of incoming) {
    if (alert && typeof alert.alert_id === 'string') byId.set(alert.alert_id, alert)
  }
  return [...byId.values()].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
}

const apiBase = () => import.meta.env.VITE_API_BASE_URL || window.location.origin

function websocketUrl() {
  if (import.meta.env.VITE_WS_URL) return import.meta.env.VITE_WS_URL
  const base = apiBase().replace(/^http/, 'ws').replace(/\/$/, '')
  return `${base}/ws`
}

function formatTimestamp(value) {
  if (!value) return 'N/A'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' })
}

function displayValue(value) {
  return value === null || value === undefined || value === '' ? 'N/A' : String(value)
}

function HealthValue({ value }) {
  if (value === null || value === undefined) return <span className="muted">NOT MEASURED</span>
  return <span className={value === true ? 'value good' : value === false ? 'value bad' : 'value'}>{String(value)}</span>
}

function ConnectionState({ state, error }) {
  const labels = { connected: 'LIVE', connecting: 'RECONNECTING', disconnected: 'DISCONNECTED' }
  const Icon = state === 'connected' ? Wifi : state === 'connecting' ? RefreshCw : WifiOff
  return (
    <div className={`connection ${state}`} title={error || labels[state]}>
      <Icon size={15} />
      <span>{labels[state]}</span>
      {error && <span className="connection-error">{error}</span>}
    </div>
  )
}

function AlertRow({ alert, selected, onSelect }) {
  return (
    <button className={`alert-row ${selected ? 'selected' : ''}`} onClick={() => onSelect(alert)}>
      <span className="severity-dot" />
      <span className="alert-row-main">
        <strong>{displayValue(alert.threat_class)}</strong>
        <span>{displayValue(alert.alert_id)} · {displayValue(alert.severity)}</span>
      </span>
      <span className="alert-row-meta">
        <span>{alert.confidence === null || alert.confidence === undefined ? 'N/A' : `${(alert.confidence * 100).toFixed(1)}%`}</span>
        <time>{formatTimestamp(alert.timestamp)}</time>
      </span>
      <ChevronRight size={16} />
    </button>
  )
}

function Detail({ alert }) {
  if (!alert) return <div className="empty-detail">Select an alert to inspect its evidence and lineage.</div>
  const endpoints = `${displayValue(alert.src_ip)}:${displayValue(alert.src_port)}  ->  ${displayValue(alert.dst_ip)}:${displayValue(alert.dst_port)}`
  return (
    <div className="detail-content">
      <div className="detail-heading">
        <div>
          <span className="eyebrow">SELECTED ALERT</span>
          <h2>{displayValue(alert.threat_class)}</h2>
        </div>
        <span className="status-pill">{displayValue(alert.status)}</span>
      </div>
      <dl className="detail-grid">
        <DetailItem label="Alert ID" value={alert.alert_id} />
        <DetailItem label="Timestamp" value={formatTimestamp(alert.timestamp)} />
        <DetailItem label="Flow ID" value={alert.flow_id} />
        <DetailItem label="Confidence" value={alert.confidence == null ? null : `${(alert.confidence * 100).toFixed(1)}%`} />
        <DetailItem label="Source / destination" value={endpoints} />
        <DetailItem label="Protocol" value={alert.protocol} />
        <DetailItem label="Model" value={alert.model} />
        <DetailItem label="Model version" value={alert.model_version} />
        <DetailItem label="Feature schema" value={alert.feature_schema} />
      </dl>
      <section className="detail-section"><h3>Evidence</h3><pre>{JSON.stringify(alert.evidence || {}, null, 2)}</pre></section>
      <section className="detail-section"><h3>Event / capture time</h3><pre>{JSON.stringify({ timestamp: alert.timestamp, observed_at: alert.timing?.observed_at }, null, 2)}</pre></section>
      <section className="detail-section"><h3>Processing / inference timing</h3><pre>{JSON.stringify(Object.fromEntries(Object.entries(alert.timing || {}).filter(([key]) => !['observed_at', 'delivered_at'].includes(key))), null, 2)}</pre></section>
      <section className="detail-section"><h3>Dashboard delivery timing</h3><pre>{JSON.stringify({ delivered_at: alert.timing?.delivered_at, delivery_time: alert.latency_durations?.delivery_time, capture_to_dashboard: alert.latency_durations?.capture_to_dashboard }, null, 2)}</pre></section>
      <section className="detail-section"><h3>Available latency durations</h3><pre>{JSON.stringify(alert.latency_durations || {}, null, 2)}</pre></section>
    </div>
  )
}

function DetailItem({ label, value }) {
  return <div><dt>{label}</dt><dd>{displayValue(value)}</dd></div>
}

function RuntimeStatus({ health, error }) {
  const fields = ['service_started', 'service_ready', 'worker_alive', 'model_validation_ok', 'storage_ok', 'capture_connected', 'runtime_mode']
  return (
    <section className="panel status-panel">
      <div className="panel-title"><span><Server size={16} /> Runtime status</span><span className="live-mark"><CircleDot size={13} /> API</span></div>
      {error && <InlineError message={error} />}
      <div className="status-list">
        <div className="status-line" key="status"><span>status</span><HealthValue value={health?.status} /></div>
        {fields.map((field) => <div className="status-line" key={field}><span>{field.replaceAll('_', ' ')}</span><HealthValue value={health?.[field]} /></div>)}
      </div>
      {health?.detector_health && <section className="detail-section health-extra"><h3>Detector health</h3><pre>{JSON.stringify(health.detector_health, null, 2)}</pre></section>}
      {Array.isArray(health?.runtime_failures) && health.runtime_failures.length > 0 && <section className="detail-section health-extra"><h3>Runtime failures</h3><pre>{JSON.stringify(health.runtime_failures, null, 2)}</pre></section>}
    </section>
  )
}

function Metrics({ stats, error }) {
  const counters = stats?.orchestrator || {}
  const latency = stats?.latency || {}
  return (
    <section className="panel metrics-panel">
      <div className="panel-title"><span><Activity size={16} /> Runtime metrics</span></div>
      {error && <InlineError message={error} />}
      <div className="counter-grid">
        {['events_received', 'events_processed', 'detector_invocations', 'detector_failures', 'alerts_produced'].map((name) => <div className="counter" key={name}><span>{name.replaceAll('_', ' ')}</span><strong>{counters[name] ?? 'N/A'}</strong></div>)}
      </div>
      <div className="latency-table-wrap">
        <table className="latency-table"><thead><tr><th>Latency</th><th>P50</th><th>P95</th><th>P99</th><th>MAX</th></tr></thead><tbody>
          {LATENCY_METRICS.map((name) => <LatencyRow key={name} name={name} metric={latency[name]} />)}
        </tbody></table>
      </div>
    </section>
  )
}

function LatencyRow({ name, metric }) {
  const value = (key) => metric?.[key] == null ? 'N/A' : `${(metric[key] * 1000).toFixed(2)} ms`
  return <tr><td>{name.replaceAll('_', ' ')}</td><td>{value('p50')}</td><td>{value('p95')}</td><td>{value('p99')}</td><td>{value('max')}</td></tr>
}

function InlineError({ message }) {
  return <div className="inline-error"><AlertTriangle size={15} /> <span>{message}</span></div>
}

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [selected, setSelected] = useState(null)
  const [health, setHealth] = useState(null)
  const [stats, setStats] = useState(null)
  const [restError, setRestError] = useState('')
  const [socketError, setSocketError] = useState('')
  const [connection, setConnection] = useState('connecting')
  const [detailError, setDetailError] = useState('')
  const reconnectAttempt = useRef(0)
  const socketRef = useRef(null)

  useEffect(() => {
    let alive = true
    Promise.all([fetch(`${apiBase()}/alerts`), fetch(`${apiBase()}/health`), fetch(`${apiBase()}/stats`)]).then(async ([alertsResponse, healthResponse, statsResponse]) => {
      if (!alertsResponse.ok || !healthResponse.ok || !statsResponse.ok) throw new Error('Backend REST request failed')
      const [history, nextHealth, nextStats] = await Promise.all([alertsResponse.json(), healthResponse.json(), statsResponse.json()])
      if (!Array.isArray(history) || !isRecord(nextHealth) || !isRecord(nextStats)) throw new Error('Backend returned an invalid response')
      if (alive) { setAlerts((current) => mergeAlerts(current, history.filter(isAlert))); setHealth(nextHealth); setStats(nextStats); setRestError('') }
    }).catch((error) => { if (alive) setRestError(error.message) })
    return () => { alive = false }
  }, [])

  useEffect(() => {
    const id = selected?.alert_id
    if (typeof id !== 'string') return
    let active = true
    fetch(`${apiBase()}/alerts/${encodeURIComponent(id)}`).then(async (response) => {
      if (!response.ok) throw new Error(`Alert details request failed (${response.status})`)
      const payload = await response.json()
      if (!isAlert(payload)) throw new Error('Backend returned invalid alert details')
      if (active) { setSelected(payload); setDetailError('') }
    }).catch((error) => { if (active) setDetailError(error.message) })
    return () => { active = false }
  }, [selected?.alert_id])

  useEffect(() => {
    let active = true
    let reconnectTimer
    const connect = () => {
      if (!active) return
      setConnection('connecting')
      const socket = new WebSocket(websocketUrl())
      socketRef.current = socket
      socket.onopen = () => { reconnectAttempt.current = 0; setConnection('connected'); setSocketError('') }
      socket.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data)
          if (!isAlert(alert)) throw new Error('Malformed alert message')
          setAlerts((current) => mergeAlerts(current, [alert]))
          setSelected((current) => current?.alert_id === alert.alert_id ? alert : current)
        } catch (error) { setSocketError(error.message) }
      }
      socket.onerror = () => setSocketError('WebSocket connection failed')
      socket.onclose = () => {
        if (!active) return
        setConnection('disconnected')
        if (reconnectAttempt.current < MAX_RECONNECT_ATTEMPTS) {
          const delay = 1000 * (2 ** reconnectAttempt.current)
          reconnectAttempt.current += 1
          setConnection('connecting')
          reconnectTimer = window.setTimeout(connect, delay)
        } else setSocketError('Reconnect limit reached')
      }
    }
    connect()
    return () => { active = false; window.clearTimeout(reconnectTimer); socketRef.current?.close() }
  }, [])

  const activeAlert = useMemo(() => alerts.find((alert) => alert.alert_id === selected?.alert_id) || selected, [alerts, selected])
  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark">S</span><div><strong>SPECTRA</strong><span>SOC RUNTIME</span></div></div>
        <div className="topbar-right"><ConnectionState state={connection} error={socketError} /><span className="topbar-date">{new Date().toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}</span></div>
      </header>
      <section className="hero"><div><span className="eyebrow">PASSIVE THREAT DETECTION</span><h1>Live alert operations</h1><p>Signals arriving from the standardized SPECTRA runtime.</p></div><div className="hero-signal"><Radio size={18} /><span>WebSocket delivery path</span><b>{connection === 'connected' ? 'ACTIVE' : connection.toUpperCase()}</b></div></section>
      <div className="dashboard-grid">
        <aside className="sidebar"><RuntimeStatus health={health} error={restError} /><Metrics stats={stats} error={restError} /></aside>
        <section className="feed panel"><div className="panel-title"><span><span className="pulse" /> Alert feed <b className="count">{alerts.length}</b></span><span className="feed-note">History + live updates</span></div>{restError && <InlineError message="History and runtime data are unavailable; preserving the last valid state." />}{alerts.length === 0 ? <div className="empty-feed">No alerts have been delivered.</div> : <div className="alert-list">{alerts.map((alert) => <AlertRow key={alert.alert_id} alert={alert} selected={activeAlert?.alert_id === alert.alert_id} onSelect={setSelected} />)}</div>}</section>
        <section className="detail panel">{detailError && <InlineError message={detailError} />}<Detail alert={activeAlert} /></section>
      </div>
      <footer><span>IN-MEMORY RUNTIME</span><span>Measured values only</span></footer>
    </main>
  )
}

function isRecord(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) }
function isAlert(value) { return isRecord(value) && typeof value.alert_id === 'string' && typeof value.timestamp === 'string' && typeof value.threat_class === 'string' }
