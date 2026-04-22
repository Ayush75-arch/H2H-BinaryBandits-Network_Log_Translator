/**
 * App.jsx — SOC Dashboard (rebuilt)
 *
 * Flow:
 *   1. Analyst pastes logs → clicks Analyze (or enables live stream)
 *   2. useLiveLogs() streams/processes logs → populates logs, incidents, stats
 *   3. LogTable renders all logs; analyst clicks row → setSelectedLog(log)
 *   4. LogDetailsPanel shows full detail for selected log
 *   5. IncidentsPanel shows active incidents from useLiveLogs().incidents
 *   6. QueryPanel receives logs/incidents/stats as context → ask(q, context)
 *
 * Layout:
 *   Topbar
 *   ┌────────────┬──────────────────────────────┬──────────────┐
 *   │ LEFT 280px │ CENTER                        │ RIGHT 380px  │
 *   │ AnalyzeInput│ Stats bar                    │ LogDetailsPanel│
 *   │ Live stats │ LogTable                      │ IncidentsPanel │
 *   │            │ QueryPanel (bottom)           │              │
 *   └────────────┴──────────────────────────────┴──────────────┘
 *   Status bar
 */

import { useState, useEffect } from 'react'
import { api } from './api.js'
import { useLiveLogs } from './hooks/useLiveLogs.js'
import AnalyzeInput   from './components/AnalyzeInput.jsx'
import LogTable       from './components/LogTable.jsx'
import LogDetailsPanel from './components/LogDetailsPanel.jsx'
import QueryPanel     from './components/QueryPanel.jsx'
import BenchmarkPanel from './components/BenchmarkPanel.jsx'

// ── Stat tile ──────────────────────────────────────────────────────────────

function StatTile({ label, value, accent }) {
  const color = {
    red:    '#f87171',
    orange: '#fb923c',
    yellow: '#fbbf24',
    green:  '#4ade80',
    blue:   '#60a5fa',
    gray:   '#4b5563',
  }[accent] || '#4b5563'

  return (
    <div className="panel" style={{ padding: '7px 12px', minWidth: 90, flexShrink: 0 }}>
      <div style={{ fontSize: 9, color: '#4b5563', textTransform: 'uppercase',
        letterSpacing: '0.08em', marginBottom: 2 }}>
        {label}
      </div>
      <div className="font-mono" style={{ fontSize: 18, fontWeight: 600,
        color, lineHeight: 1 }}>
        {value ?? '—'}
      </div>
    </div>
  )
}

// ── Active Incidents Panel ─────────────────────────────────────────────────

function IncidentsPanel({ incidents, selectedLog, onSelectIncident }) {
  if (!incidents?.length) {
    return (
      <div style={{
        padding: '10px 14px',
        borderBottom: '1px solid #1a2332',
      }}>
        <div className="section-title" style={{ marginBottom: 6 }}>Active Incidents</div>
        <div style={{ fontSize: 11, color: '#1f2937', fontStyle: 'italic' }}>
          No incidents detected
        </div>
      </div>
    )
  }

  return (
    <div style={{ borderBottom: '1px solid #1a2332' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 14px 6px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="status-dot status-offline blink" />
          <span style={{ fontSize: 10, fontWeight: 600, color: '#f87171',
            textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Active Incidents
          </span>
          <span className="font-mono" style={{ fontSize: 10, color: '#374151' }}>
            ({incidents.length})
          </span>
        </div>
      </div>

      <div style={{ maxHeight: 180, overflowY: 'auto' }}>
        {incidents.map((inc, i) => {
          const sevCls = {
            CRITICAL: '#f87171',
            HIGH:     '#fb923c',
            MEDIUM:   '#fbbf24',
            LOW:      '#60a5fa',
          }[inc.severity] || '#9ca3af'

          const badgeCls = {
            CRITICAL: 'badge-critical',
            HIGH:     'badge-high',
            MEDIUM:   'badge-medium',
            LOW:      'badge-low',
          }[inc.severity] || 'badge-info'

          const isActive = selectedLog?.source_ip === inc.ip

          return (
            <div
              key={inc.ip || i}
              onClick={() => onSelectIncident(inc)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 14px',
                borderBottom: '1px solid #1a2332',
                cursor: 'pointer',
                background: isActive
                  ? 'rgba(239,68,68,0.07)'
                  : 'transparent',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => {
                if (!isActive) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'
              }}
              onMouseLeave={e => {
                if (!isActive) e.currentTarget.style.background = 'transparent'
              }}
            >
              {/* Left accent */}
              <div style={{
                width: 2, alignSelf: 'stretch', background: sevCls,
                borderRadius: 1, flexShrink: 0,
              }} />

              {/* IP */}
              <span className="code-tag" style={{ flexShrink: 0 }}>{inc.ip}</span>

              {/* Severity */}
              <span className={`badge ${badgeCls}`} style={{ flexShrink: 0 }}>
                {inc.severity === 'CRITICAL' && <span className="blink">● </span>}
                {inc.severity}
              </span>

              {/* Risk score */}
              <span className="font-mono" style={{
                fontSize: 10, color: '#4b5563', marginLeft: 'auto', flexShrink: 0,
              }}>
                Risk {inc.risk_score ?? '?'}/100
              </span>

              {/* Compromised indicator */}
              {inc.is_compromised && (
                <span style={{ fontSize: 10, color: '#f87171', fontWeight: 700 }}>⚠</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Topbar incident pill ───────────────────────────────────────────────────

function IncidentPill({ incidents }) {
  if (!incidents?.length) return null
  const top = incidents[0]
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '4px 10px',
      background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
      borderRadius: 3, fontSize: 11,
    }}>
      <span className="status-dot status-offline blink" />
      <span style={{ color: '#f87171', fontWeight: 600 }}>
        {incidents.length} incident{incidents.length !== 1 ? 's' : ''}
      </span>
      <span style={{ color: '#374151' }}>·</span>
      <span className="code-tag">{top.ip}</span>
      <span style={{ color: '#6b7280' }}>{top.severity} · Risk {top.risk_score}/100</span>
    </div>
  )
}

// ── App ────────────────────────────────────────────────────────────────────

export default function App() {
  const [mode,      setMode]      = useState('batch')
  const [logType,   setLogType]   = useState('auto')
  const [input,     setInput]     = useState('')
  const [loading,   setLoading]   = useState(false)
  const [results,   setResults]   = useState(null)
  const [error,     setError]     = useState(null)
  const [tab,       setTab]       = useState('logs')
  const [backendOk, setBackendOk] = useState(null)
  const [liveMode,  setLiveMode]  = useState(false)
  const [liveDelay, setLiveDelay] = useState(450)

  // Selected row state
  const [selectedIdx,      setSelectedIdx]      = useState(null)
  const [selectedLog,      setSelectedLog]      = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)

  // Live stream hook — single source of truth
  const {
    isLive, logs: liveLogs, incidents: liveIncidents, stats: liveStats,
    compromiseAlerts, streamDone, recommendedActions,
    startStream, stopStream, resetStream,
  } = useLiveLogs()

  // Backend health
  useEffect(() => {
    api.health()
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false))
  }, [])

  // ── Analyze / stream ──────────────────────────────────────────────────────

  async function handleAnalyze() {
    if (!input.trim()) return

    if (liveMode && mode === 'batch') {
      const lines = input.trim().split('\n').filter(l => l.trim())
      resetStream()
      setResults(null)
      setError(null)
      clearSelection()
      startStream(lines, liveDelay)
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    clearSelection()

    try {
      let data
      if (mode === 'single') {
        data = await api.analyzeSingle(input.trim())
        data._single = true
      } else {
        const lines = input.trim().split('\n').filter(l => l.trim())
        data = await api.analyzeBatch(lines)
      }
      setResults(data)
    } catch (err) {
      setError(err.message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  function handleModeChange(m) {
    setMode(m)
    setResults(null)
    setError(null)
    setInput('')
    clearSelection()
    if (isLive) resetStream()
  }

  function clearSelection() {
    setSelectedIdx(null)
    setSelectedLog(null)
    setSelectedIncident(null)
  }

  // Click row in LogTable → setSelectedLog
  function handleSelectLog(idx, log) {
    if (selectedIdx === idx) { clearSelection(); return }
    setSelectedIdx(idx)
    setSelectedLog(log)
    // Correlate incident by source IP
    const inc = allIncidents.find(i => i.ip === log.source_ip) || null
    setSelectedIncident(inc)
  }

  // Click incident in IncidentsPanel
  function handleSelectIncident(inc) {
    setSelectedIncident(inc)
    // Find most severe log for this IP to populate details
    const match = displayLogs
      .filter(l => l.source_ip === inc.ip)
      .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))[0]
    if (match) {
      const idx = displayLogs.indexOf(match)
      setSelectedIdx(idx)
      setSelectedLog(match)
    }
  }

  // ── Derived display data ──────────────────────────────────────────────────

  const showLive    = liveMode && mode === 'batch' && (isLive || streamDone || liveLogs.length > 0)
  const displayLogs = showLive
    ? liveLogs
    : results
      ? (results._single ? [results] : (results.logs || []))
      : []

  // incidents come from useLiveLogs() in live mode, or from batch results
  const allIncidents = showLive ? liveIncidents : (results?.incidents || [])

  // Context passed to QueryPanel — always populated from live hook or batch results
  const queryLogs       = displayLogs
  const queryIncidents  = allIncidents
  const queryStats      = liveStats || (results ? {
    total_processed: displayLogs.length,
    anomaly_count:   displayLogs.filter(l => l.is_anomaly).length,
    incident_count:  allIncidents.length,
    top_severity:    results.top_severity,
  } : null)
  const queryRecommendedActions = showLive
    ? recommendedActions
    : (results?.recommended_actions || [])

  const anomalyCount  = displayLogs.filter(l => l.is_anomaly).length
  const criticalCount = displayLogs.filter(l => l.severity === 'CRITICAL').length
  const highCount     = displayLogs.filter(l => l.severity === 'HIGH').length

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh',
      overflow: 'hidden', background: '#0b1220' }}>

      {/* Topbar */}
      <div className="topbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none"
            stroke="#3b82f6" strokeWidth="1.8">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', letterSpacing: '-0.01em' }}>
            NLT<span style={{ color: '#3b82f6' }}> ·</span> Network Log Translator
          </span>
          <span className="font-mono" style={{ fontSize: 9, color: '#374151', marginLeft: 2 }}>v9</span>
        </div>

        {/* Tab nav */}
        <div style={{ display: 'flex', gap: 2, marginLeft: 20 }}>
          {[{ id: 'logs', label: 'Log Analysis' }, { id: 'benchmark', label: 'Benchmark' }].map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '4px 11px', fontSize: 12, fontWeight: 500, borderRadius: 3,
                cursor: 'pointer', transition: 'all 0.1s',
                background: tab === t.id ? '#1f2937' : 'transparent',
                color: tab === t.id ? '#e2e8f0' : '#4b5563',
                border: `1px solid ${tab === t.id ? '#374151' : 'transparent'}`,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Mode toggle */}
        {tab === 'logs' && (
          <div style={{ display: 'flex', gap: 2, marginLeft: 10 }}>
            {['single', 'batch'].map(m => (
              <button
                key={m}
                onClick={() => handleModeChange(m)}
                style={{
                  padding: '3px 9px', fontSize: 11, fontWeight: 500, borderRadius: 3,
                  cursor: 'pointer', textTransform: 'capitalize',
                  background: mode === m ? '#1d4ed8' : '#111827',
                  color: mode === m ? '#fff' : '#6b7280',
                  border: `1px solid ${mode === m ? '#2563eb' : '#1f2937'}`,
                }}
              >
                {m}
              </button>
            ))}
          </div>
        )}

        {/* Right: incident pill + backend status */}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          {allIncidents.length > 0 && <IncidentPill incidents={allIncidents} />}

          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
            <span className={`status-dot ${
              backendOk === true  ? 'status-online blink' :
              backendOk === false ? 'status-offline'      : 'status-pending'
            }`} />
            <span className="font-mono" style={{
              color: backendOk === true ? '#4ade80' : backendOk === false ? '#f87171' : '#fbbf24',
            }}>
              {backendOk === true ? 'CONNECTED' : backendOk === false ? 'OFFLINE' : 'CONNECTING'}
            </span>
            <span style={{ color: '#374151' }}>·</span>
            <span className="font-mono" style={{ color: '#374151', fontSize: 10 }}>127.0.0.1:8000</span>
          </div>
        </div>
      </div>

      {/* Main content */}
      {tab === 'benchmark' ? (
        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          <BenchmarkPanel />
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

          {/* LEFT: log input sidebar */}
          <div style={{
            width: 280, flexShrink: 0, display: 'flex', flexDirection: 'column',
            borderRight: '1px solid #1f2937', background: '#0e1724',
          }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <AnalyzeInput
                mode={mode}
                value={input}
                onChange={setInput}
                logType={logType}
                onLogTypeChange={setLogType}
                onAnalyze={handleAnalyze}
                loading={loading || isLive}
                liveMode={liveMode}
                onLiveModeToggle={() => { setLiveMode(v => !v); if (isLive) resetStream() }}
                isLive={isLive}
                liveDelay={liveDelay}
                onLiveDelayChange={setLiveDelay}
              />
            </div>

            {/* Pipeline steps — idle state */}
            {!loading && !isLive && !results && !error && !streamDone && (
              <div style={{ borderTop: '1px solid #1f2937', padding: '10px 12px' }}>
                <div className="section-title">Pipeline</div>
                {[
                  { n: '01', label: 'Parse',     color: '#60a5fa', desc: '8 log formats'    },
                  { n: '02', label: 'Detect',    color: '#fb923c', desc: 'Anomaly rules'    },
                  { n: '03', label: 'Classify',  color: '#f87171', desc: 'Severity scoring' },
                  { n: '04', label: 'Correlate', color: '#c084fc', desc: 'IP grouping'      },
                  { n: '05', label: 'Explain',   color: '#4ade80', desc: 'LLaMA 3 analysis' },
                ].map(s => (
                  <div key={s.n} style={{ display: 'flex', alignItems: 'center', gap: 8,
                    padding: '4px 0', borderBottom: '1px solid #1a2332', fontSize: 11 }}>
                    <span className="font-mono" style={{ color: s.color, width: 20,
                      fontSize: 10, opacity: 0.7 }}>{s.n}</span>
                    <span style={{ color: '#9ca3af', width: 60 }}>{s.label}</span>
                    <span style={{ color: '#374151', fontSize: 10 }}>{s.desc}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Live stream status */}
            {showLive && (
              <div style={{ borderTop: '1px solid #1f2937', padding: '8px 12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between',
                  alignItems: 'center', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                    {isLive ? (
                      <><span className="status-dot status-online blink" />
                        <span style={{ color: '#4ade80', fontWeight: 600 }}>STREAMING</span></>
                    ) : (
                      <><span className="status-dot" style={{ background: '#374151' }} />
                        <span style={{ color: '#6b7280' }}>Complete</span></>
                    )}
                  </div>
                  {isLive && (
                    <button onClick={stopStream} className="btn btn-danger"
                      style={{ fontSize: 10, padding: '2px 7px' }}>
                      Stop
                    </button>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, fontSize: 10 }}>
                  {[
                    { label: 'Processed', val: liveStats?.total_processed ?? liveLogs.length },
                    { label: 'Anomalies', val: liveStats?.anomaly_count   ?? 0 },
                    { label: 'Incidents', val: liveIncidents.length },
                    { label: 'Top Sev',   val: liveStats?.top_severity    || '—' },
                  ].map(s => (
                    <div key={s.label} style={{ background: '#111827', border: '1px solid #1f2937',
                      borderRadius: 3, padding: '4px 7px' }}>
                      <div style={{ color: '#374151' }}>{s.label}</div>
                      <div className="font-mono" style={{ color: '#9ca3af', fontWeight: 600 }}>
                        {s.val}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* CENTER: stats bar + table + query panel */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column',
            overflow: 'hidden', minWidth: 0 }}>

            {/* Stats bar */}
            {displayLogs.length > 0 && (
              <div style={{
                display: 'flex', gap: 6, padding: '6px 12px',
                background: '#0a0f1a', borderBottom: '1px solid #1f2937',
                overflowX: 'auto', flexShrink: 0,
              }}>
                <StatTile label="Total"     value={displayLogs.length} accent="gray" />
                <StatTile label="Anomalies" value={anomalyCount}
                  accent={anomalyCount  > 0 ? 'orange' : 'gray'} />
                <StatTile label="Incidents" value={allIncidents.length}
                  accent={allIncidents.length > 0 ? 'red' : 'gray'} />
                <StatTile label="Critical"  value={criticalCount}
                  accent={criticalCount > 0 ? 'red' : 'gray'} />
                <StatTile label="High"      value={highCount}
                  accent={highCount     > 0 ? 'orange' : 'gray'} />
                {results?.time_to_clarity && (
                  <StatTile label="Analysis time" value={results.time_to_clarity} accent="blue" />
                )}
              </div>
            )}

            {/* Compromise alert banner */}
            {compromiseAlerts.length > 0 && (
              <div style={{
                background: 'rgba(239,68,68,0.08)', borderBottom: '1px solid rgba(239,68,68,0.2)',
                padding: '5px 14px', display: 'flex', alignItems: 'center',
                gap: 10, flexShrink: 0,
              }}>
                <span className="status-dot status-offline blink" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#f87171',
                  textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Account Compromise Detected
                </span>
                {compromiseAlerts.slice(0, 3).map(a => (
                  <span key={a._id || a.ip} className="code-tag">{a.ip}</span>
                ))}
              </div>
            )}

            {/* Error banner */}
            {error && (
              <div style={{
                background: 'rgba(239,68,68,0.07)', borderBottom: '1px solid rgba(239,68,68,0.15)',
                padding: '7px 14px', display: 'flex', alignItems: 'center',
                gap: 10, flexShrink: 0,
              }}>
                <span style={{ fontSize: 11, color: '#f87171' }}>✕ {error}</span>
                <button onClick={handleAnalyze} className="btn"
                  style={{ fontSize: 11, padding: '3px 8px', marginLeft: 'auto' }}>
                  Retry
                </button>
              </div>
            )}

            {/* Table header */}
            <div className="panel-header" style={{
              borderRadius: 0, borderLeft: 'none', borderRight: 'none', borderTop: 'none',
              justifyContent: 'space-between', flexShrink: 0,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                  stroke="#4b5563" strokeWidth="2">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <path d="M3 9h18M9 21V9"/>
                </svg>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#6b7280',
                  textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Log Events
                </span>
                {displayLogs.length > 0 && (
                  <span className="font-mono" style={{ fontSize: 10, color: '#374151' }}>
                    ({displayLogs.length})
                  </span>
                )}
                {isLive && (
                  <span className="blink" style={{ fontSize: 10, color: '#4ade80' }}>● LIVE</span>
                )}
              </div>
              {selectedLog && (
                <span style={{ fontSize: 10, color: '#4b5563' }}>
                  Row {selectedIdx + 1} selected · click to deselect
                </span>
              )}
            </div>

            {/* Log table */}
            <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              {loading ? (
                <div style={{ padding: 20 }}>
                  {[...Array(7)].map((_, i) => (
                    <div key={i} className="shimmer" style={{
                      height: 31, marginBottom: 1, borderRadius: 2,
                      opacity: 1 - i * 0.1,
                    }} />
                  ))}
                </div>
              ) : (
                <LogTable
                  logs={displayLogs}
                  selectedIndex={selectedIdx}
                  onSelectLog={handleSelectLog}
                />
              )}
            </div>

            {/* Query panel — always receives logs/incidents/stats as context */}
            <QueryPanel
              logs={queryLogs}
              incidents={queryIncidents}
              stats={queryStats}
              recommendedActions={queryRecommendedActions}
            />
          </div>

          {/* RIGHT: detail panel + incidents panel */}
          <div style={{
            width: 380, minWidth: 340, maxWidth: 420, flexShrink: 0,
            display: 'flex', flexDirection: 'column',
            background: '#0e1724', borderLeft: '1px solid #1f2937',
            overflow: 'hidden',
          }}>
            {/* Active Incidents — uses useLiveLogs().incidents */}
            <IncidentsPanel
              incidents={allIncidents}
              selectedLog={selectedLog}
              onSelectIncident={handleSelectIncident}
            />

            {/* Log detail for selected row */}
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
              <LogDetailsPanel
                log={selectedLog}
                incident={selectedIncident}
                recommendedActions={queryRecommendedActions}
                onClose={clearSelection}
              />
            </div>
          </div>
        </div>
      )}

      {/* Status bar */}
      <div style={{
        background: '#070e1a', borderTop: '1px solid #1a2332',
        height: 22, display: 'flex', alignItems: 'center',
        padding: '0 14px', gap: 16, fontSize: 10, color: '#374151', flexShrink: 0,
      }}>
        <span>NLT · H2H-BinaryBandits · Hack2Hire 1.0 · TJIT 2026</span>
        <span style={{ marginLeft: 'auto', fontFamily: 'monospace' }}>
          {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
      </div>
    </div>
  )
}
