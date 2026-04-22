import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { SEV_CONFIG } from '../data.js'

const LOG_TYPE_ICONS = {
  syslog:'⬛', rfc5424:'🔷', vpc_flow:'☁️', snmp:'📡',
  web:'🌐', firewall:'🔥', windows:'🪟', dns:'🔎', unknown:'❓',
}

export default function LogCard({ log, index }) {
  const [expanded, setExpanded] = useState(false)
  const cfg  = SEV_CONFIG[log.severity] || SEV_CONFIG.INFO
  const icon = LOG_TYPE_ICONS[log.log_type] || LOG_TYPE_ICONS.unknown
  const conf = log.confidence_score ?? 50
  const risk = log.risk_score ?? 0

  const isCompromised = log.is_compromised
  const borderClass   = isCompromised
    ? 'border-red-500/50 shadow-lg shadow-red-500/15'
    : log.incident
      ? 'border-red-500/25'
      : `border-slate-700/40`

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, type: 'spring', stiffness: 400, damping: 35 }}
      whileHover={{ scale: 1.01, boxShadow: isCompromised
        ? '0 0 20px rgba(239,68,68,0.15)'
        : log.is_anomaly ? '0 0 16px rgba(34,211,238,0.08)' : 'none'
      }}
      className={`glass rounded-2xl border p-4 cursor-pointer transition-colors duration-200
        ${borderClass} ${isCompromised ? 'bg-red-950/10' : ''}`}
      onClick={() => setExpanded(v => !v)}
    >
      {isCompromised && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="flex items-center gap-2 mb-3 px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/30"
        >
          <motion.span
            animate={{ scale: [1,1.2,1] }}
            transition={{ duration: 1.5, repeat: Infinity }}
            className="w-1.5 h-1.5 rounded-full bg-red-400"
          />
          <span className="text-xs font-bold text-red-400">ACCOUNT COMPROMISED — Failed logins followed by successful auth</span>
        </motion.div>
      )}

      <div className="flex items-start gap-3">
        <motion.div
          animate={log.severity === 'CRITICAL' ? { opacity: [1, 0.4, 1] } : {}}
          transition={{ duration: 1.5, repeat: Infinity }}
          className={`mt-0.5 flex-shrink-0 w-1 min-h-[40px] rounded-full ${cfg.dot}`}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <motion.span
              whileHover={{ scale: 1.05 }}
              className={`text-xs font-semibold px-2 py-0.5 rounded-md border ${cfg.bg} ${cfg.color} ${cfg.border}`}
            >
              {log.severity}
            </motion.span>
            <span className="text-xs text-slate-400 font-mono bg-slate-800/60 px-2 py-0.5 rounded-md border border-slate-700/30">
              {icon} {log.log_type || 'unknown'}
            </span>
            {log.is_anomaly && (
              <span className="text-xs font-medium text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded-md border border-orange-500/20">⚠ Anomaly</span>
            )}
            {log.incident && (
              <span className="text-xs font-semibold text-red-400 bg-red-500/10 px-2 py-0.5 rounded-md border border-red-500/30">🔗 Incident</span>
            )}
            <span className="ml-auto text-xs text-slate-600 font-mono">#{String(index + 1).padStart(2, '0')}</span>
          </div>

          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs text-slate-500">Source IP</span>
            <code className="text-sm text-cyan-300 font-mono">{log.source_ip || 'unknown'}</code>
          </div>

          {log.reason && log.reason !== 'Normal activity' && (
            <p className="text-xs text-slate-400 leading-relaxed">{log.reason}</p>
          )}

          {log.is_anomaly && (
            <div className="flex items-center gap-4 mt-2">
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-600">Conf</span>
                <span className={`text-xs font-bold ${conf >= 80 ? 'text-cyan-400' : conf >= 60 ? 'text-yellow-400' : 'text-slate-400'}`}>{conf}%</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-600">Risk</span>
                <span className={`text-xs font-bold ${risk >= 80 ? 'text-red-400' : risk >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>{risk}/100</span>
              </div>
              <span className="ml-auto text-xs text-slate-600">{expanded ? '▲' : '▼'}</span>
            </div>
          )}

          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="mt-3 pt-3 border-t border-slate-700/30">
                  {log.explanation && (
                    <div className="mb-2">
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className="text-xs font-semibold text-indigo-400">🧠 AI Insight</span>
                        <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-medium" style={{fontSize: 9, letterSpacing: '0.06em'}}>SOC GRADE</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{log.explanation}</p>
                    </div>
                  )}
                  {log.attack_summary && !log.attack_summary.includes('Normal activity') && (
                    <div className="mt-2 pt-2 border-t border-slate-700/20">
                      <span className="text-xs text-slate-500 font-medium">⛓ Attack Summary</span>
                      <div className="flex flex-wrap items-center gap-1 mt-1">
                        {log.attack_summary.split('->').map((part, i, arr) => (
                          <span key={i} className="flex items-center gap-1">
                            <span className={`text-xs px-1.5 py-0.5 rounded border font-medium ${
                              i === 0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                              : i === arr.length - 1 ? 'text-red-400 bg-red-500/10 border-red-500/20'
                              : 'text-slate-400 bg-slate-700/40 border-slate-600/30'
                            }`}>{part.trim()}</span>
                            {i < arr.length - 1 && <span className="text-slate-600 text-xs">→</span>}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {log.timestamp && (
                    <p className="text-xs text-slate-600 font-mono mt-2">{log.timestamp}</p>
                  )}
                  {log.incident && log.incident_reason && (
                    <p className="text-xs text-red-400/80 mt-1">🔗 {log.incident_reason}</p>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {!expanded && log.timestamp && (
            <p className="text-xs text-slate-600 font-mono mt-1.5">{log.timestamp}</p>
          )}
        </div>
      </div>
    </motion.div>
  )
}
