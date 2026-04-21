/**
 * LogTable.jsx
 *
 * SOC analyst log table.
 *
 * Columns: Timestamp | Source IP | Severity | Reason | Risk Score | Status
 *
 * Rules:
 *   - reason always shown: log.reason || "No specific trigger identified"
 *   - row class: row-${log.severity.toLowerCase()}
 *   - clicking a row calls onSelectLog(i, log) → triggers setSelectedLog(log)
 */

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

function fmtTs(ts) {
  if (!ts) return '—'
  const s = String(ts)
  const iso = s.match(/\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/)
  if (iso) return `${iso[1]} ${iso[2]}`
  const sys = s.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/)
  if (sys) return sys[1]
  return s.slice(0, 19)
}

function RiskScore({ score }) {
  if (score == null) return <span style={{ color: '#374151' }}>—</span>
  const color =
    score >= 80 ? '#f87171' :
    score >= 60 ? '#fb923c' :
    score >= 40 ? '#fbbf24' : '#4b5563'
  return (
    <span
      className="font-mono"
      style={{ fontSize: 11, color, fontWeight: score >= 60 ? 600 : 400 }}
    >
      {score}<span style={{ color: '#374151', fontWeight: 400 }}>/100</span>
    </span>
  )
}

export default function LogTable({ logs, selectedIndex, onSelectLog }) {
  if (!logs?.length) {
    return (
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexDirection: 'column', gap: 10, color: '#1f2937',
      }}>
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none"
          stroke="currentColor" strokeWidth="1">
          <rect x="3" y="3" width="18" height="18" rx="2"/>
          <path d="M3 9h18M9 21V9"/>
        </svg>
        <span style={{ fontSize: 12 }}>Paste logs and click Analyze to begin</span>
      </div>
    )
  }

  return (
    <div style={{ overflowX: 'auto', overflowY: 'auto', flex: 1 }}>
      <table className="soc-table">
        <colgroup>
          <col style={{ width: 3 }} />
          <col style={{ width: 132 }} />
          <col style={{ width: 130 }} />
          <col style={{ width: 96 }} />
          <col />
          <col style={{ width: 80 }} />
          <col style={{ width: 88 }} />
        </colgroup>
        <thead>
          <tr>
            <th style={{ padding: 0 }} />
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Reason</th>
            <th>Risk Score</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, i) => {
            const sev      = (log.severity || 'INFO').toUpperCase()
            const rowCls   = `row-${sev.toLowerCase()}`
            const badgeCls = SEV_BADGE[sev] || 'badge-info'
            const barCls   = SEV_BAR[sev]   || 'bar-info'
            const reason   = (log.reason && log.reason.trim())
              ? log.reason.trim()
              : 'No specific trigger identified'
            const dimReason = reason === 'No specific trigger identified'
            const isNew     = log._isNew

            return (
              <tr
                key={log._id || i}
                className={`${rowCls}${selectedIndex === i ? ' selected' : ''}${isNew ? ' log-new' : ''}`}
                onClick={() => onSelectLog(i, log)}
              >
                <td style={{ padding: 0, width: 3 }}>
                  <div className={barCls} style={{ width: 3, minHeight: 32 }} />
                </td>

                <td>
                  <span className="font-mono" style={{ fontSize: 11, color: '#4b5563' }}>
                    {fmtTs(log.timestamp)}
                  </span>
                </td>

                <td>
                  <span className="code-tag">{log.source_ip || '—'}</span>
                </td>

                <td>
                  <span className={`badge ${badgeCls}`}>
                    {sev === 'CRITICAL' && <span className="blink">● </span>}
                    {sev}
                  </span>
                </td>

                {/* REASON — always shown, never empty */}
                <td style={{ maxWidth: 0 }}>
                  <span
                    title={reason}
                    style={{
                      fontSize: 11,
                      color: dimReason ? '#374151' : '#cbd5e1',
                      fontStyle: dimReason ? 'italic' : 'normal',
                      display: 'block',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {reason}
                  </span>
                </td>

                <td><RiskScore score={log.risk_score} /></td>

                <td>
                  <span className={`badge ${log.is_anomaly ? 'badge-anomaly' : 'badge-normal'}`}>
                    {log.is_anomaly ? '⚠ Anomaly' : '✓ Normal'}
                  </span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      <style>{`
        @keyframes logFlash {
          from { background: rgba(59,130,246,0.12); }
          to   { background: transparent; }
        }
        .log-new td { animation: logFlash 0.6s ease-out; }
      `}</style>
    </div>
  )
}
