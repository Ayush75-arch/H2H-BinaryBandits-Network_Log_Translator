import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { SEV_CONFIG } from '../data.js'

function TimelineItem({ item, index, total }) {
  const cfg = SEV_CONFIG[item.severity] || SEV_CONFIG.INFO
  const isLast = index === total - 1
  const isCompromise = item.event && (
    item.event.toLowerCase().includes('accepted password') ||
    item.event.toLowerCase().includes('accepted publickey')
  )
  return (
    <motion.div
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.06, type: 'spring', stiffness: 400, damping: 35 }}
      className="flex gap-3 relative"
    >
      {!isLast && <div className="absolute left-[11px] top-6 bottom-0 w-px bg-slate-700/60" />}
      <div className={`flex-shrink-0 mt-1 w-5 h-5 rounded-full border-2 flex items-center justify-center z-10
        ${isCompromise ? 'bg-red-500/30 border-red-400 shadow-lg shadow-red-500/30' : `${cfg.bg} ${cfg.border}`}`}>
        <div className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      </div>
      <div className={`flex-1 pb-4 ${isCompromise ? 'bg-red-500/5 border border-red-500/20 rounded-xl px-3 py-2 -ml-1' : ''}`}>
        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
          {isCompromise && (
            <motion.span
              animate={{ opacity: [1, 0.6, 1] }} transition={{ duration: 1.5, repeat: Infinity }}
              className="text-xs font-bold text-red-400 bg-red-500/20 px-2 py-0.5 rounded-md border border-red-500/30"
            >⚠ COMPROMISE</motion.span>
          )}
          <span className={`text-xs font-semibold ${cfg.color}`}>{item.severity}</span>
          <span className="text-xs text-slate-500 font-mono bg-slate-800/60 px-1.5 rounded">{item.log_type}</span>
          {item.time && <span className="text-xs text-slate-600 font-mono ml-auto">{item.time}</span>}
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">{item.event}</p>
      </div>
    </motion.div>
  )
}

export default function IncidentModal({ incident, onClose }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  if (!incident) return null

  const cfg = SEV_CONFIG[incident.severity] || SEV_CONFIG.INFO
  const stages = incident.attack_chain?.stages || []
  const stageReasons = incident.attack_chain?.stage_reasons || {}
  const timeline = incident.timeline || []
  const stageColors = {
    Recon: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
    Intrusion: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
    Compromise: 'text-red-400 bg-red-500/15 border-red-500/30',
    'Post-Compromise': 'text-purple-400 bg-purple-500/15 border-purple-500/30',
  }

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />
        <motion.div
          initial={{ opacity: 0, scale: 0.92, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.92, y: 20 }}
          transition={{ type: 'spring', stiffness: 380, damping: 30 }}
          className={`relative z-10 w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-3xl border
            ${incident.is_compromised ? 'border-red-500/40 shadow-2xl shadow-red-500/20' : `${cfg.border} shadow-2xl`}
            bg-[#0d1526]`}
          onClick={e => e.stopPropagation()}
          style={{ scrollbarWidth: 'thin' }}
        >
          <div className={`p-6 border-b ${incident.is_compromised ? 'border-red-500/20' : 'border-slate-700/40'}`}>
            <div className="flex items-start justify-between gap-4">
              <div>
                {incident.is_compromised && (
                  <motion.div
                    animate={{ opacity: [1, 0.7, 1] }} transition={{ duration: 2, repeat: Infinity }}
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-xs font-bold mb-3"
                  >
                    🚨 ACCOUNT COMPROMISED
                  </motion.div>
                )}
                <div className="flex items-center gap-3 flex-wrap">
                  <span className={`text-xs font-bold px-2 py-1 rounded-lg border ${cfg.bg} ${cfg.color} ${cfg.border}`}>{incident.severity}</span>
                  <code className="text-lg font-mono text-cyan-300">{incident.ip}</code>
                  <span className="text-xs text-slate-400">{incident.event_count} events</span>
                </div>
                <p className="text-sm text-slate-300 mt-2 font-medium">
                  {incident.attack_chain?.final_classification || incident.incident_type}
                </p>
              </div>
              <motion.button
                whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}
                onClick={onClose}
                className="flex-shrink-0 w-8 h-8 rounded-xl bg-slate-800/80 border border-slate-700/40 text-slate-400 hover:text-slate-200 hover:bg-slate-700/60 transition-all text-sm"
              >✕</motion.button>
            </div>
            <div className="grid grid-cols-2 gap-3 mt-4">
              {[
                { label: 'Confidence', value: incident.confidence_score, bar: 'from-cyan-500 to-violet-500', textColor: 'text-cyan-400' },
                { label: 'Risk Score', value: incident.risk_score,
                  bar: incident.risk_score >= 90 ? 'bg-red-500' : 'bg-orange-500',
                  textColor: incident.risk_score >= 90 ? 'text-red-400' : 'text-orange-400',
                  suffix: '/100' }
              ].map(s => (
                <div key={s.label} className="bg-slate-800/60 rounded-xl p-3 border border-slate-700/30">
                  <div className="text-xs text-slate-500 mb-1">{s.label}</div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${s.value}%` }}
                        transition={{ delay: 0.3, duration: 0.8, ease: 'easeOut' }}
                        className={`h-full rounded-full ${s.bar.includes(' ') ? `bg-gradient-to-r ${s.bar}` : s.bar}`}
                      />
                    </div>
                    <span className={`text-sm font-bold ${s.textColor}`}>{s.value}{s.suffix || '%'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">AI Analysis</h3>
              <p className="text-sm text-slate-200 leading-relaxed bg-slate-800/40 rounded-xl p-4 border border-slate-700/30">
                {incident.explanation}
              </p>
            </div>

            {stages.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Attack Chain</h3>
                <div className="flex items-center gap-1 flex-wrap">
                  {stages.map((stage, i) => (
                    <motion.div
                      key={stage}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.1 }}
                      className="flex items-center gap-1"
                    >
                      <span className={`px-3 py-1.5 rounded-lg text-xs font-semibold border ${stageColors[stage] || 'text-slate-400 bg-slate-700/30 border-slate-600/30'}`}>
                        {stage}
                      </span>
                      {i < stages.length - 1 && <span className="text-slate-600 text-sm">→</span>}
                    </motion.div>
                  ))}
                </div>
                <div className="mt-2 space-y-1">
                  {stages.map(stage => stageReasons[stage] && (
                    <div key={stage} className="flex gap-2 text-xs">
                      <span className="text-slate-600 w-28 flex-shrink-0">{stage}:</span>
                      <span className="text-slate-400">{stageReasons[stage]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {timeline.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">
                  Event Timeline ({timeline.length} events)
                </h3>
                <div className="space-y-0">
                  {timeline.map((item, i) => (
                    <TimelineItem key={i} item={item} index={i} total={timeline.length} />
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
