import { useState } from 'react'
import { SINGLE_SAMPLES, BATCH_ATTACK_SCENARIO } from '../data.js'
import LogTypeSelector from './LogTypeSelector.jsx'

export default function LogInput({ mode, value, onChange, logType, onLogTypeChange, onAnalyze, loading }) {
  const [copied, setCopied] = useState(false)

  function loadSample() {
    if (mode === 'batch') {
      onChange(BATCH_ATTACK_SCENARIO)
    } else {
      onChange(SINGLE_SAMPLES[logType] || SINGLE_SAMPLES.syslog)
    }
  }

  function handleClear() {
    onChange('')
  }

  const placeholder = mode === 'single'
    ? `Paste a single log line here...\n\nExample:\nJun 10 14:23:01 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58321`
    : `Paste multiple log lines here (one per line)...\n\nSupports mixed formats — Syslog, VPC Flow, SNMP, Apache, Firewall, Windows, DNS\n\nClick "Load Attack Scenario" for a demo.`

  const lineCount = value ? value.split('\n').filter(l => l.trim()).length : 0

  return (
    <div className="flex flex-col gap-4">
      {/* Controls row */}
      <div className="flex items-end gap-3 flex-wrap">
        {mode === 'single' && (
          <div className="flex-1 min-w-48">
            <LogTypeSelector value={logType} onChange={onLogTypeChange} />
          </div>
        )}
        {mode === 'batch' && (
          <div className="flex items-center gap-2 px-3 py-2 glass rounded-xl border border-violet-500/20">
            <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
            <span className="text-xs text-violet-300 font-medium">Batch mode — auto-detects all formats</span>
          </div>
        )}
        <div className="flex gap-2 ml-auto">
          <button
            onClick={loadSample}
            className="px-3 py-2 text-xs font-medium rounded-lg border border-cyan-500/30 text-cyan-400
                       hover:bg-cyan-500/10 hover:border-cyan-400/50 transition-all duration-200"
          >
            {mode === 'batch' ? '⚡ Load Attack Scenario' : '⚡ Load Sample'}
          </button>
          {value && (
            <button
              onClick={handleClear}
              className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-600/50 text-slate-400
                         hover:bg-slate-500/10 hover:border-slate-500/50 transition-all duration-200"
            >
              ✕ Clear
            </button>
          )}
        </div>
      </div>

      {/* Textarea */}
      <div className="relative group">
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-500/5 to-violet-500/5 opacity-0 group-focus-within:opacity-100 transition-opacity duration-300 pointer-events-none" />
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          rows={mode === 'batch' ? 12 : 6}
          className="w-full glass border border-slate-700/60 rounded-2xl px-5 py-4
                     text-sm font-mono text-slate-200 placeholder-slate-600
                     focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/10
                     transition-all duration-200 scrollbar-thin resize-y leading-relaxed"
        />
        {/* Line count badge */}
        {mode === 'batch' && value && (
          <div className="absolute bottom-3 right-3 px-2 py-0.5 rounded-md bg-slate-800/80 border border-slate-700/50 text-xs text-slate-400">
            {lineCount} line{lineCount !== 1 ? 's' : ''}
          </div>
        )}
      </div>

      {/* Analyze button */}
      <button
        onClick={onAnalyze}
        disabled={loading || !value.trim()}
        className={`relative w-full py-3.5 rounded-2xl font-medium text-sm tracking-wide
                    transition-all duration-300 overflow-hidden group
                    ${loading || !value.trim()
                      ? 'bg-slate-800/60 text-slate-500 cursor-not-allowed border border-slate-700/40'
                      : 'bg-gradient-to-r from-cyan-600/80 to-violet-600/80 hover:from-cyan-500/90 hover:to-violet-500/90 text-white border border-cyan-500/30 hover:border-cyan-400/50 shadow-lg hover:shadow-cyan-500/20 hover:-translate-y-0.5'
                    }`}
      >
        {!loading && !(!value.trim()) && (
          <span className="absolute inset-0 bg-gradient-to-r from-cyan-400/0 via-white/5 to-cyan-400/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700" />
        )}
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Analyzing…
          </span>
        ) : (
          <span className="flex items-center justify-center gap-2">
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
            </svg>
            {mode === 'batch' ? `Analyze ${lineCount || ''} Logs` : 'Analyze Log'}
          </span>
        )}
      </button>
    </div>
  )
}
