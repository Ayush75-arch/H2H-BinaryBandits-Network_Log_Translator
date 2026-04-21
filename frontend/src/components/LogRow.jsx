import { SEV_CONFIG } from '../data.js'

const SEV_ROW = {
  CRITICAL: 'row-critical',
  HIGH:     'row-high',
  MEDIUM:   'row-medium',
  LOW:      'row-low',
  INFO:     'row-info',
}
const SEV_BADGE = {
  CRITICAL: 'badge-critical',
  HIGH:     'badge-high',
  MEDIUM:   'badge-medium',
  LOW:      'badge-low',
  INFO:     'badge-info',
}
const SEV_BAR = {
  CRITICAL: 'bar-critical',
  HIGH:     'bar-high',
  MEDIUM:   'bar-medium',
  LOW:      'bar-low',
  INFO:     'bar-info',
}

function fmtTimestamp(ts) {
  if (!ts) return '—'
  // Try to shorten common timestamp formats
  const s = String(ts)
  // ISO
  const isoMatch = s.match(/T(\d{2}:\d{2}:\d{2})/)
  if (isoMatch) return s.slice(0, 10) + ' ' + isoMatch[1]
  // Syslog: "Jun 10 14:23:01"
  const syslogMatch = s.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/)
  if (syslogMatch) return syslogMatch[1]
  return s.slice(0, 19)
}

export default function LogRow({ log, index, selected, onClick }) {
  const sev     = log.severity || 'INFO'
  const rowCls  = SEV_ROW[sev]  || 'row-info'
  const badgeCls = SEV_BADGE[sev] || 'badge-info'
  const barCls  = SEV_BAR[sev]  || 'bar-info'
  const reason  = log.reason || 'No specific trigger identified'
  const isAnomaly = log.is_anomaly
  const risk    = log.risk_score ?? 0
  const conf    = log.confidence_score ?? 0

  return (
    <tr
      className={`${rowCls} ${selected ? 'selected' : ''}`}
      onClick={onClick}
    >
      {/* Severity bar */}
      <td style={{ width: 3, padding: 0 }}>
        <div className={`${barCls} h-full`} style={{ width: 3, minHeight: 32 }} />
      </td>

      {/* Timestamp */}
      <td style={{ width: 140 }}>
        <span className="font-mono text-slate-500" style={{ fontSize: 11 }}>
          {fmtTimestamp(log.timestamp)}
        </span>
      </td>

      {/* Source IP */}
      <td style={{ width: 130 }}>
        <span className="code-tag">{log.source_ip || '—'}</span>
      </td>

      {/* Event Type */}
      <td style={{ width: 120 }}>
        <span className="text-slate-400" style={{ fontSize: 11 }}>
          {log.log_type || 'unknown'}
        </span>
      </td>

      {/* Severity */}
      <td style={{ width: 100 }}>
        <span className={`badge ${badgeCls}`}>
          {sev === 'CRITICAL' && <span className="blink">●</span>}
          {sev}
        </span>
      </td>

      {/* Reason */}
      <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>
        <span
          className={reason === 'No specific trigger identified' ? 'text-slate-600' : 'text-slate-300'}
          title={reason}
          style={{ fontSize: 11 }}
        >
          {reason}
        </span>
      </td>

      {/* Risk Score */}
      <td style={{ width: 80 }}>
        <span style={{ fontSize: 11 }} className={
          risk >= 80 ? 'sev-critical font-semibold' :
          risk >= 60 ? 'sev-high font-semibold' :
          risk >= 40 ? 'sev-medium' : 'text-slate-500'
        }>
          {risk > 0 ? `${risk}/100` : '—'}
        </span>
      </td>

      {/* Confidence */}
      <td style={{ width: 80 }}>
        <span style={{ fontSize: 11 }} className={
          conf >= 80 ? 'text-slate-300' : conf >= 50 ? 'text-slate-400' : 'text-slate-600'
        }>
          {conf > 0 ? `${conf}%` : '—'}
        </span>
      </td>

      {/* Status */}
      <td style={{ width: 90 }}>
        <span className={`badge ${isAnomaly ? 'badge-anomaly' : 'badge-normal'}`}>
          {isAnomaly ? '⚠ Anomaly' : '✓ Normal'}
        </span>
      </td>
    </tr>
  )
}
