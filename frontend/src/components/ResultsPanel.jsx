import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import SummaryCard from './SummaryCard.jsx'
import LogCard from './LogCard.jsx'
import IncidentModal from './IncidentModal.jsx'
import { SEV_CONFIG } from '../data.js'

const tabVariants = {
  initial: { opacity: 0, x: 12 },
  animate: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 400, damping: 35 } },
  exit:    { opacity: 0, x: -12, transition: { duration: 0.15 } },
}

function IncidentCard({ incident, onClick }) {
  const cfg = SEV_CONFIG[incident.severity] || SEV_CONFIG.INFO
  const stages = incident.attack_chain?.stages || []
  const stageColors = {
    Recon: 'text-blue-400', Intrusion: 'text-orange-400',
    Compromise: 'text-red-400', 'Post-Compromise': 'text-purple-400',
  }
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.01, boxShadow: incident.is_compromised
        ? '0 0 24px rgba(239,68,68,0.18)' : '0 0 16px rgba(34,211,238,0.08)' }}
      transition={{ type: 'spring', stiffness: 400, damping: 35 }}
      className={`rounded-2xl border p-4 bg-gradient-to-br from-slate-800/50 to-slate-900/50
        cursor-pointer ${incident.is_compromised ? 'border-red-500/50 shadow-lg shadow-red-500/15' : cfg.border}`}
      onClick={onClick}
    >
      {incident.is_compromised && (
        <motion.div
          animate={{ opacity: [1,0.7,1] }} transition={{ duration: 2, repeat: Infinity }}
          className="flex items-center gap-1.5 mb-2"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
          <span className="text-xs font-bold text-red-400 uppercase tracking-wide">Account Compromised</span>
        </motion.div>
      )}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-red-400 text-sm">🔗</span>
            <code className="text-sm text-cyan-300 font-mono font-medium">{incident.ip}</code>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}>
              {incident.event_count} events · {incident.severity}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">{incident.attack_chain?.final_classification || incident.incident_type}</p>
        </div>
        <span className="text-xs text-red-400/70 font-medium whitespace-nowrap">View →</span>
      </div>
      {stages.length > 0 && (
        <div className="flex items-center gap-1 flex-wrap mb-3">
          {stages.map((s, i) => (
            <span key={s} className="flex items-center gap-0.5">
              <span className={`text-xs font-medium ${stageColors[s] || 'text-slate-400'}`}>{s}</span>
              {i < stages.length - 1 && <span className="text-slate-700 text-xs">→</span>}
            </span>
          ))}
        </div>
      )}
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'Confidence', val: incident.confidence_score, bar: 'bg-gradient-to-r from-cyan-500 to-violet-500', text: 'text-cyan-400', suffix: '%' },
          { label: 'Risk',       val: incident.risk_score,       bar: incident.risk_score >= 90 ? 'bg-red-500' : 'bg-orange-500',
            text: incident.risk_score >= 90 ? 'text-red-400' : 'text-orange-400', suffix: '/100' },
        ].map(s => (
          <div key={s.label}>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-600">{s.label}</span>
              <span className={`font-medium ${s.text}`}>{s.val}{s.suffix}</span>
            </div>
            <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${s.val}%` }}
                transition={{ delay: 0.2, duration: 0.7, ease: 'easeOut' }}
                className={`h-full rounded-full ${s.bar}`}
              />
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500 mt-2 truncate">{incident.explanation}</p>
    </motion.div>
  )
}

function RecommendationsPanel({ recs }) {
  if (!recs?.length) return null
  const urgencyStyle = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
    HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
    MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    INFO:     'text-slate-400 bg-slate-500/10 border-slate-600/20',
  }
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="glass rounded-3xl border border-slate-700/40 p-5"
    >
      <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
        <span className="w-5 h-5 rounded-md bg-violet-500/20 border border-violet-500/30 flex items-center justify-center text-xs">📋</span>
        Recommended Actions
      </h3>
      <div className="flex flex-col gap-2">
        {recs.map((r, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 + i * 0.06 }}
            className={`flex items-center gap-3 px-3 py-2.5 rounded-xl border ${urgencyStyle[r.urgency] || urgencyStyle.INFO} transition-all`}
          >
            <span className="text-base flex-shrink-0">{r.icon}</span>
            <span className="text-sm">{r.action}</span>
            {r.urgency !== 'INFO' && (
              <span className={`ml-auto text-xs font-medium uppercase tracking-wide ${urgencyStyle[r.urgency]?.split(' ')[0]}`}>
                {r.urgency}
              </span>
            )}
          </motion.div>
        ))}
      </div>
    </motion.div>
  )
}

// Skeleton loaders
function LogSkeleton() {
  return (
    <div className="glass rounded-2xl border border-slate-700/30 p-4">
      <div className="flex gap-3">
        <div className="w-1 min-h-[40px] rounded-full bg-slate-700/60 shimmer" />
        <div className="flex-1 space-y-2">
          <div className="flex gap-2">
            <div className="h-5 w-16 rounded-md bg-slate-700/60 shimmer" />
            <div className="h-5 w-20 rounded-md bg-slate-700/60 shimmer" />
            <div className="h-5 w-12 rounded-md bg-slate-700/60 shimmer ml-auto" />
          </div>
          <div className="h-4 w-32 rounded bg-slate-700/60 shimmer" />
          <div className="h-3 w-48 rounded bg-slate-700/60 shimmer" />
        </div>
      </div>
    </div>
  )
}

function IncidentSkeleton() {
  return (
    <div className="rounded-2xl border border-slate-700/30 p-4 bg-slate-800/30">
      <div className="space-y-3">
        <div className="flex gap-2">
          <div className="h-5 w-28 rounded bg-slate-700/60 shimmer" />
          <div className="h-5 w-20 rounded bg-slate-700/60 shimmer" />
        </div>
        <div className="h-3 w-40 rounded bg-slate-700/60 shimmer" />
        <div className="grid grid-cols-2 gap-2">
          <div className="h-8 rounded-lg bg-slate-700/60 shimmer" />
          <div className="h-8 rounded-lg bg-slate-700/60 shimmer" />
        </div>
      </div>
    </div>
  )
}

export function ResultsSkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <div className="glass rounded-3xl border border-slate-700/30 p-5 space-y-4">
        <div className="flex gap-3">
          <div className="h-8 w-24 rounded-lg bg-slate-700/60 shimmer" />
          <div className="h-8 w-28 rounded-lg bg-slate-700/60 shimmer" />
          <div className="h-8 w-16 rounded-lg bg-slate-700/60 shimmer ml-auto" />
        </div>
        <div className="h-10 w-full rounded-xl bg-slate-700/60 shimmer" />
        <div className="grid grid-cols-3 gap-3">
          {[0,1,2].map(i => <div key={i} className="h-16 rounded-xl bg-slate-700/60 shimmer" />)}
        </div>
      </div>
      <div className="flex flex-col gap-2">
        {[0,1,2].map(i => <IncidentSkeleton key={i} />)}
      </div>
      <div className="flex flex-col gap-2">
        {[0,1,2,3].map(i => <LogSkeleton key={i} />)}
      </div>
    </div>
  )
}

export default function ResultsPanel({ data, mode }) {
  const [activeTab,      setActiveTab]  = useState('overview')
  const [showAll,        setShowAll]    = useState(false)
  const [selectedIncident, setSelected] = useState(null)

  if (!data) return null

  const logs      = mode === 'batch' ? (data.logs || []) : [data]
  const incidents = data.incidents || []
  const recs      = data.recommended_actions || []
  const displayLogs = showAll ? logs : logs.slice(0, 6)

  const tabs = [
    { id: 'overview',  label: 'Overview' },
    { id: 'incidents', label: `Incidents (${incidents.length})` },
    { id: 'logs',      label: `Logs (${logs.length})` },
    { id: 'actions',   label: 'Actions' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col gap-5"
    >
      <SummaryCard data={data} mode={mode} />

      {/* Tab nav */}
      <div className="flex gap-1 p-1 rounded-2xl glass border border-slate-700/40">
        {tabs.map(t => (
          <motion.button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            whileTap={{ scale: 0.97 }}
            className={`flex-1 py-2 px-2 rounded-xl text-xs font-medium transition-all duration-200
              ${activeTab === t.id
                ? 'bg-slate-700/60 text-slate-100 border border-slate-600/40'
                : 'text-slate-500 hover:text-slate-300'}`}
          >
            {t.label}
          </motion.button>
        ))}
      </div>

      {/* Tab content with AnimatePresence for slide transitions */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          variants={tabVariants}
          initial="initial"
          animate="animate"
          exit="exit"
        >
          {/* OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="flex flex-col gap-4">
              {incidents.some(i => i.is_compromised) && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.97 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="rounded-2xl border border-red-500/40 bg-red-500/10 p-4"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <motion.span animate={{ scale: [1,1.3,1] }} transition={{ duration: 1.5, repeat: Infinity }} className="w-2 h-2 rounded-full bg-red-400" />
                    <span className="text-sm font-bold text-red-300">Account Compromise Detected</span>
                  </div>
                  <p className="text-xs text-red-400/80">Failed login attempts followed by successful authentication. Immediate action required.</p>
                </motion.div>
              )}
              {incidents.slice(0, 2).map((inc, i) => (
                <IncidentCard key={inc.ip} incident={inc} onClick={() => setSelected(inc)} />
              ))}
              {incidents.length > 2 && (
                <button onClick={() => setActiveTab('incidents')} className="text-xs text-cyan-400 hover:text-cyan-300 text-center py-1 transition-colors">
                  View all {incidents.length} incidents →
                </button>
              )}
              {logs.slice(0, 3).map((log, i) => <LogCard key={i} log={log} index={i} />)}
            </div>
          )}

          {/* INCIDENTS */}
          {activeTab === 'incidents' && (
            <div className="flex flex-col gap-3">
              {incidents.length > 0
                ? incidents.map((inc, i) => <IncidentCard key={inc.ip} incident={inc} onClick={() => setSelected(inc)} />)
                : <div className="text-center py-8 text-slate-500 text-sm">No correlated incidents found</div>
              }
            </div>
          )}

          {/* LOGS */}
          {activeTab === 'logs' && (
            <div className="flex flex-col gap-2">
              {displayLogs.map((log, i) => <LogCard key={i} log={log} index={i} />)}
              {logs.length > 6 && (
                <motion.button
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setShowAll(v => !v)}
                  className="mt-1 w-full py-2 rounded-xl border border-slate-700/40 text-xs text-slate-400 hover:bg-slate-800/40 hover:text-slate-200 transition-all"
                >
                  {showAll ? '▲ Show less' : `▼ Show ${logs.length - 6} more`}
                </motion.button>
              )}
            </div>
          )}

          {/* ACTIONS */}
          {activeTab === 'actions' && <RecommendationsPanel recs={recs} />}
        </motion.div>
      </AnimatePresence>

      {/* Always show recs in overview */}
      {activeTab === 'overview' && <RecommendationsPanel recs={recs.slice(0, 3)} />}

      {selectedIncident && (
        <IncidentModal incident={selectedIncident} onClose={() => setSelected(null)} />
      )}
    </motion.div>
  )
}
