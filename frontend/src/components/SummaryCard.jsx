import { motion } from 'framer-motion'
import { SEV_CONFIG } from '../data.js'

function AnimatedNumber({ value }) {
  return (
    <motion.span
      key={value}
      initial={{ opacity: 0, y: -8, scale: 1.3 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ type: 'spring', stiffness: 500, damping: 30 }}
    >
      {value}
    </motion.span>
  )
}

export default function SummaryCard({ data, mode }) {
  if (!data) return null

  const logs          = mode === 'batch' ? (data.logs || []) : [data]
  const totalLogs     = logs.length
  const anomalyCount  = data.anomaly_count  ?? logs.filter(l => l.is_anomaly).length
  const incidentCount = data.incident_count ?? (data.incidents?.length ?? 0)
  const ttc           = data.time_to_clarity || '—'
  const summary       = data.summary || ''
  const hasCompromise = data.incidents?.some(i => i.is_compromised)

  const topSevLog = logs.reduce((m, l) => {
    const o = { CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1 }
    return (o[l.severity]||0) > (o[m.severity]||0) ? l : m
  }, { severity: 'INFO' })
  const topSev = topSevLog.severity
  const cfg    = SEV_CONFIG[topSev] || SEV_CONFIG.INFO

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: 'spring', stiffness: 400, damping: 35 }}
      className={`glass rounded-3xl border p-5
        ${topSev === 'CRITICAL' || hasCompromise ? 'border-red-500/30' : 'border-slate-700/40'}`}
    >
      <div className="flex items-center gap-3 mb-4">
        <motion.span
          whileHover={{ scale: 1.05 }}
          className={`text-xs font-bold px-3 py-1.5 rounded-lg border ${cfg.bg} ${cfg.color} ${cfg.border} flex items-center gap-1.5`}
        >
          {topSev === 'CRITICAL' && (
            <motion.span
              animate={{ opacity: [1,0.3,1] }}
              transition={{ duration: 1.2, repeat: Infinity }}
              className="w-1.5 h-1.5 rounded-full bg-red-400"
            />
          )}
          {topSev}
        </motion.span>
        {incidentCount > 0 && (
          <motion.span
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-400 flex items-center gap-1"
          >
            ⚠ {incidentCount} INCIDENT{incidentCount > 1 ? 'S' : ''}
          </motion.span>
        )}
        <span className="ml-auto text-xs text-slate-500 font-mono flex items-center gap-1">⏱ {ttc}</span>
      </div>

      {summary && (
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="text-sm text-slate-200 leading-relaxed mb-4"
        >
          {summary}
        </motion.p>
      )}

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Logs',  value: totalLogs,     color: 'text-slate-300'  },
          { label: 'Anomalies',   value: anomalyCount,  color: 'text-orange-400' },
          { label: 'Incidents',   value: incidentCount, color: 'text-red-400'    },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 + i * 0.07 }}
            className="bg-slate-800/50 rounded-xl p-3 border border-slate-700/30 text-center"
          >
            <div className={`text-xl font-bold ${s.color}`}>
              <AnimatedNumber value={s.value} />
            </div>
            <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  )
}
