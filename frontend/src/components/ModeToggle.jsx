export default function ModeToggle({ mode, onChange }) {
  return (
    <div className="inline-flex p-1 rounded-xl glass border border-cyan-500/20">
      {['single', 'batch'].map((m) => (
        <button
          key={m}
          onClick={() => onChange(m)}
          className={`px-5 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
            mode === m
              ? 'bg-gradient-to-r from-cyan-500/30 to-violet-500/30 text-cyan-300 border border-cyan-500/40 shadow-lg'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          {m === 'single' ? '⬜ Single Log' : '⬛ Batch Mode'}
        </button>
      ))}
    </div>
  )
}
