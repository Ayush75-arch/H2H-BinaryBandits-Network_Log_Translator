import { LOG_TYPES } from '../data.js'

export default function LogTypeSelector({ value, onChange }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-medium text-slate-400 tracking-wider uppercase">Log Format</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="glass border border-cyan-500/20 rounded-xl px-4 py-2.5 text-sm text-slate-200 bg-transparent
                   focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                   transition-all duration-200 cursor-pointer appearance-none
                   hover:border-cyan-500/40"
        style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 12px center', paddingRight: '36px' }}
      >
        <option value="auto" style={{ background: '#0a1628' }}>🔍 Auto-detect</option>
        {LOG_TYPES.map((t) => (
          <option key={t.value} value={t.value} style={{ background: '#0a1628' }}>
            {t.label}
          </option>
        ))}
      </select>
    </div>
  )
}
