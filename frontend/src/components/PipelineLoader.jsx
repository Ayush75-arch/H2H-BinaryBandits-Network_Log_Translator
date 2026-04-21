import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const STAGES = [
  { id:1, label:'Parsing logs',           sub:'Extracting fields & normalizing formats', icon:'⬛', color:'cyan'    },
  { id:2, label:'Detecting anomalies',    sub:'Running 8 rule-based detectors',          icon:'🔍', color:'violet'  },
  { id:3, label:'Classifying severity',   sub:'CRITICAL / HIGH / MEDIUM / LOW / INFO',   icon:'🛡️', color:'orange'  },
  { id:4, label:'Correlating incidents',  sub:'Grouping anomalies by source IP',         icon:'🔗', color:'pink'    },
  { id:5, label:'Generating explanation', sub:'LLaMA 3 forming plain-English summary',   icon:'✨', color:'emerald' },
]
const COLOR_MAP = {
  cyan:    { bar:'from-cyan-500 to-cyan-400',       text:'text-cyan-400',    border:'border-cyan-500/40',    bg:'bg-cyan-500/10'    },
  violet:  { bar:'from-violet-500 to-violet-400',   text:'text-violet-400',  border:'border-violet-500/40',  bg:'bg-violet-500/10'  },
  orange:  { bar:'from-orange-500 to-orange-400',   text:'text-orange-400',  border:'border-orange-500/40',  bg:'bg-orange-500/10'  },
  pink:    { bar:'from-pink-500 to-pink-400',       text:'text-pink-400',    border:'border-pink-500/40',    bg:'bg-pink-500/10'    },
  emerald: { bar:'from-emerald-500 to-emerald-400', text:'text-emerald-400', border:'border-emerald-500/40', bg:'bg-emerald-500/10' },
}

export default function PipelineLoader({ active }) {
  const [currentStage, setCurrentStage] = useState(0)
  const [progress,     setProgress]     = useState(0)
  const [doneStages,   setDoneStages]   = useState([])

  useEffect(() => {
    if (!active) { setCurrentStage(0); setProgress(0); setDoneStages([]); return }
    const durations = [600, 800, 500, 600, 2500]
    let stageIdx = 0, prog = 0, rafId
    function tick() {
      const dur = durations[stageIdx] || 800
      prog += 100 / (dur / 50)
      if (prog >= 100) {
        prog = 0
        setDoneStages(d => [...d, stageIdx + 1])
        stageIdx++
        if (stageIdx >= STAGES.length) return
      }
      setCurrentStage(stageIdx)
      setProgress(Math.min(prog, 100))
      rafId = setTimeout(tick, 50)
    }
    tick()
    return () => clearTimeout(rafId)
  }, [active])

  if (!active) return null

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="glass rounded-3xl border border-cyan-500/20 p-6"
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="flex gap-1">
          {[0,1,2].map(i => (
            <motion.div
              key={i}
              animate={{ y: [0, -5, 0] }}
              transition={{ duration: 0.6, repeat: Infinity, delay: i * 0.15 }}
              className="w-2 h-2 rounded-full bg-cyan-400"
            />
          ))}
        </div>
        <span className="text-sm font-medium text-cyan-300 tracking-wide">Pipeline Running</span>
        <div className="ml-auto text-xs text-slate-500 font-mono">{doneStages.length}/{STAGES.length} stages</div>
      </div>

      <div className="relative overflow-hidden rounded-full mb-6 h-px bg-slate-700/50">
        <motion.div
          animate={{ x: ['-100%', '200%'] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
          className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
        />
      </div>

      <div className="flex flex-col gap-3">
        {STAGES.map((stage, i) => {
          const isDone    = doneStages.includes(stage.id)
          const isActive  = currentStage === i && !isDone
          const isPending = !isDone && !isActive
          const c         = COLOR_MAP[stage.color]

          return (
            <motion.div
              key={stage.id}
              layout
              animate={isActive ? { boxShadow: `0 0 0 1px rgba(34,211,238,0.4), 0 0 30px rgba(34,211,238,0.1)` } : {}}
              className={`relative rounded-2xl border p-4 transition-all duration-500
                ${isDone   ? 'border-emerald-500/30 bg-emerald-500/5' : ''}
                ${isActive ? `${c.border} ${c.bg}` : ''}
                ${isPending ? 'border-slate-700/40 bg-slate-800/20 opacity-40' : ''}
              `}
            >
              <div className="flex items-center gap-3">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center text-base flex-shrink-0 border
                  ${isDone   ? 'bg-emerald-500/20 border-emerald-500/40' : ''}
                  ${isActive ? `${c.bg} ${c.border}` : ''}
                  ${isPending ? 'bg-slate-700/30 border-slate-600/30' : ''}
                `}>
                  {isDone ? (
                    <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type:'spring', stiffness:500 }}>
                      ✓
                    </motion.span>
                  ) : stage.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className={`text-sm font-medium ${isDone ? 'text-emerald-400' : isActive ? c.text : 'text-slate-500'}`}>
                    {stage.label}
                  </div>
                  {(isDone || isActive) && (
                    <div className="text-xs text-slate-500 mt-0.5 truncate">{stage.sub}</div>
                  )}
                </div>
                <div className={`text-xs font-mono px-2 py-0.5 rounded-md
                  ${isDone   ? 'text-emerald-400 bg-emerald-500/10' : ''}
                  ${isActive ? `${c.text} ${c.bg}` : ''}
                  ${isPending ? 'text-slate-600 bg-slate-700/30' : ''}
                `}>
                  {String(stage.id).padStart(2,'0')}
                </div>
              </div>
              {isActive && (
                <div className="mt-3 h-1 rounded-full bg-slate-700/50 overflow-hidden">
                  <motion.div
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.1 }}
                    className={`h-full rounded-full bg-gradient-to-r ${c.bar}`}
                  />
                </div>
              )}
            </motion.div>
          )
        })}
      </div>
    </motion.div>
  )
}
