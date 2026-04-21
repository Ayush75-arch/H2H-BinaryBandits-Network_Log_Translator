import { useState } from 'react'
import { SINGLE_SAMPLES, BATCH_ATTACK_SCENARIO, LOG_TYPES } from '../data.js'

export default function AnalyzeInput({
  mode, value, onChange, logType, onLogTypeChange,
  onAnalyze, loading, liveMode, onLiveModeToggle, isLive, liveDelay, onLiveDelayChange
}) {
  const lineCount = value ? value.trim().split('\n').filter(l => l.trim()).length : 0

  function loadSample() {
    if (mode === 'batch') onChange(BATCH_ATTACK_SCENARIO)
    else onChange(SINGLE_SAMPLES[logType] || SINGLE_SAMPLES.syslog)
  }

  const placeholder = mode === 'single'
    ? 'Paste a single log line here...\n\nExample:\nJun 10 14:23:01 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58321'
    : 'Paste log lines here, one per line...\n\nSupports: Syslog, RFC5424, VPC Flow, SNMP, Apache/Nginx, Firewall, Windows Event, DNS\n\nClick "Load Demo" to use an attack scenario.'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: '100%' }}>
      {/* Toolbar */}
      <div className="panel-header" style={{ gap: 6, flexWrap: 'wrap', padding: '7px 12px', borderRadius: '4px 4px 0 0' }}>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#4b5563" strokeWidth="2">
          <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
          <polyline points="9 22 9 12 15 12 15 22"/>
        </svg>
        <span style={{ fontSize: 11, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Log Input
        </span>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {mode === 'single' && (
            <select
              value={logType}
              onChange={e => onLogTypeChange(e.target.value)}
              className="soc-input"
              style={{ width: 'auto', padding: '3px 6px', fontSize: 11 }}
            >
              <option value="auto">Auto-detect</option>
              {LOG_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          )}

          {mode === 'batch' && (
            <button
              onClick={onLiveModeToggle}
              className={`btn ${liveMode ? 'btn-primary' : ''}`}
              style={{ fontSize: 11, padding: '3px 8px' }}
            >
              {liveMode && <span className="status-dot status-online blink" />}
              {liveMode ? 'LIVE ON' : '○ Live'}
            </button>
          )}

          <button onClick={loadSample} className="btn" style={{ fontSize: 11, padding: '3px 8px' }}>
            Load Demo
          </button>

          {value && (
            <button onClick={() => onChange('')} className="btn" style={{ fontSize: 11, padding: '3px 8px' }}>
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Live delay slider */}
      {liveMode && mode === 'batch' && (
        <div style={{
          background: '#0f1623', borderBottom: '1px solid #1f2937',
          padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 10
        }}>
          <span style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase', letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>
            Stream delay
          </span>
          <input
            type="range" min="100" max="1500" step="50"
            value={liveDelay}
            onChange={e => onLiveDelayChange(Number(e.target.value))}
            style={{ flex: 1 }}
          />
          <span className="font-mono" style={{ fontSize: 11, color: '#93c5fd', width: 56 }}>
            {liveDelay}ms
          </span>
        </div>
      )}

      {/* Textarea */}
      <div style={{ position: 'relative', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <textarea
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          className="soc-textarea"
          style={{
            flex: 1, minHeight: mode === 'batch' ? 200 : 100,
            borderTop: 'none', borderBottom: 'none',
            borderRadius: 0, resize: 'none'
          }}
        />
        {mode === 'batch' && value && (
          <div style={{
            position: 'absolute', bottom: 8, right: 10,
            fontSize: 10, color: '#374151', background: '#0a0f1a',
            padding: '2px 6px', borderRadius: 2, fontFamily: 'monospace'
          }}>
            {lineCount} line{lineCount !== 1 ? 's' : ''}
          </div>
        )}
      </div>

      {/* Analyze button */}
      <button
        onClick={onAnalyze}
        disabled={loading || !value.trim()}
        className={`btn ${loading || !value.trim() ? '' : 'btn-primary'}`}
        style={{
          width: '100%', justifyContent: 'center', borderRadius: '0 0 4px 4px',
          borderTop: '1px solid #1f2937', padding: '10px 16px', fontSize: 13,
          fontWeight: 600
        }}
      >
        {loading ? (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              style={{ animation: 'spin 1s linear infinite' }}>
              <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            Analyzing…
          </>
        ) : (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
            {mode === 'batch' ? `Analyze ${lineCount > 0 ? lineCount + ' ' : ''}Logs` : 'Analyze Log'}
          </>
        )}
      </button>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
