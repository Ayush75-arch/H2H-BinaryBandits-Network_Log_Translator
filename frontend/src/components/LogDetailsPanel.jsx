/**
 * LogDetailsPanel.jsx
 *
 * Right-side detail panel. Displays full structured data for the selected log row.
 * Also shows the correlated incident for that source IP if one exists.
 *
 * Layout (structured label → value):
 *   Source IP | Severity | Reason | Explanation | Risk Score | Confidence Score
 *   + attack chain, timeline, recommended actions when incident data is present
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

const CHAIN_CLASS = {
  'Recon':           'chain-recon',
  'Intrusion':       'chain-intrusion',
  'Compromise':      'chain-compromise',
  'Post-Compromise': 'chain-post',
}

// label → value row
function Row({ label, children }) {
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <span className="detail-value">{children}</span>
    </div>
  )
}

// Full-width block with multiline content (reason, explanation)
function Block({ label, children, dim }) {
  return (
    <div className="detail-row" style={{ flexDirection: 'column', gap: 5 }}>
      <span className="detail-label">{label}</span>
      <span style={{
        fontSize: 12, lineHeight: 1.7,
        color: dim ? '#374151' : '#cbd5e1',
        fontStyle: dim ? 'italic' : 'normal',
      }}>
        {children}
      </span>
    </div>
  )
}

function ScoreBar({ value, colorClass }) {
  return (
    <div className="score-bar-track">
      <div
        className={`score-bar-fill ${colorClass}`}
        style={{ width: `${Math.min(100, Math.max(0, value || 0))}%` }}
      />
    </div>
  )
}

export default function LogDetailsPanel({ log, incident, recommendedActions, onClose }) {
  if (!log && !incident) {
    return (
      <div className="detail-panel" style={{ flex: 1, alignItems: 'center', justifyContent: 'center', minHeight: 0 }}>
        <div style={{ padding: 24, color: '#1f2937', textAlign: 'center' }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.5" style={{ margin: '0 auto 10px', display: 'block', opacity: 0.4 }}>
            <path d="M15 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <path d="M15 3v5h5M8 13h8M8 17h5"/>
          </svg>
          <div style={{ fontSize: 11 }}>Select a row to inspect</div>
        </div>
      </div>
    )
  }

  const sev    = (log?.severity || incident?.severity || 'INFO').toUpperCase()
  const risk   = log?.risk_score         ?? incident?.risk_score         ?? 0
  const conf   = log?.confidence_score   ?? incident?.confidence_score   ?? 0
  const reason = (log?.reason && log.reason.trim())
    ? log.reason.trim()
    : 'No specific trigger identified'
  const dimReason = reason === 'No specific trigger identified'

  const riskColor =
    risk >= 80 ? '#f87171' :
    risk >= 60 ? '#fb923c' :
    risk >= 40 ? '#fbbf24' : '#9ca3af'

  const riskBarClass =
    risk >= 80 ? 'bar-critical' :
    risk >= 60 ? 'bar-high' :
    risk >= 40 ? 'bar-medium' : 'bar-info'

  const stages      = incident?.attack_chain?.stages        || []
  const stageReason = incident?.attack_chain?.stage_reasons || {}
  const timeline    = incident?.timeline                    || []
  const recs        = recommendedActions || incident?.recommended_actions || []

  return (
    <div className="detail-panel slide-in-right" style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>

      {/* Header */}
      <div className="panel-header" style={{ justifyContent: 'space-between', padding: '10px 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#4b5563" strokeWidth="2">
            <path d="M15 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <path d="M15 3v5h5M8 13h8M8 17h5"/>
          </svg>
          <span style={{ fontSize: 11, fontWeight: 600, color: '#6b7280',
            textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Log Detail
          </span>
        </div>
        <button onClick={onClose} className="btn" style={{ padding: '3px 8px', fontSize: 11 }}>
          ✕
        </button>
      </div>

      {/* Compromise banner */}
      {(log?.is_compromised || incident?.is_compromised) && (
        <div style={{
          background: 'rgba(239,68,68,0.1)', borderBottom: '1px solid rgba(239,68,68,0.25)',
          padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span className="status-dot status-offline blink" />
          <span style={{ fontSize: 11, fontWeight: 700, color: '#f87171',
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Account Compromise Detected
          </span>
        </div>
      )}

      {/* ── Core fields ─── */}

      <Row label="Source IP">
        <span className="code-tag">{log?.source_ip || incident?.ip || '—'}</span>
      </Row>

      <Row label="Severity">
        <span className={`badge ${SEV_BADGE[sev] || 'badge-info'}`}>
          {sev === 'CRITICAL' && <span className="blink">● </span>}
          {sev}
        </span>
      </Row>

      <Row label="Event Type">
        <span style={{ fontSize: 11, color: '#94a3b8' }}>{log?.log_type || '—'}</span>
      </Row>

      <Row label="Timestamp">
        <span className="font-mono" style={{ fontSize: 11, color: '#6b7280' }}>
          {log?.timestamp || '—'}
        </span>
      </Row>

      <Row label="Status">
        <span className={`badge ${log?.is_anomaly ? 'badge-anomaly' : 'badge-normal'}`}>
          {log?.is_anomaly ? '⚠ Anomaly' : '✓ Normal'}
        </span>
      </Row>

      {/* ── Reason — always shown ── */}
      <Block label="Reason" dim={dimReason}>
        {reason}
      </Block>

      {/* ── AI Insight (Explanation + Attack Summary) ── */}
      {(log?.explanation || incident?.explanation) && (
        <div className="detail-row" style={{ flexDirection: 'column', gap: 5 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span className="detail-label" style={{ marginBottom: 0 }}>🧠 AI Insight</span>
            <span style={{
              fontSize: 9, fontWeight: 700, letterSpacing: '0.08em',
              textTransform: 'uppercase', color: '#6366f1',
              background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)',
              borderRadius: 4, padding: '1px 5px',
            }}>SOC Grade</span>
          </div>
          <span style={{
            fontSize: 11.5, lineHeight: 1.8, color: '#cbd5e1',
            whiteSpace: 'pre-wrap', wordBreak: 'break-word', display: 'block',
          }}>
            {log?.explanation || incident?.explanation}
          </span>
        </div>
      )}

      {/* ── Attack Summary ── */}
      {(log?.attack_summary || incident?.attack_summary) && (() => {
        const summary = log?.attack_summary || incident?.attack_summary || ''
        if (summary.includes('Normal activity')) return null
        const parts = summary.split(/\s*->\s*/)
        return (
          <div className="detail-row" style={{ flexDirection: 'column', gap: 6 }}>
            <span className="detail-label">⛓ Attack Summary</span>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 4 }}>
              {parts.map((part, i) => (
                <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{
                    fontSize: 10, fontWeight: 600,
                    color: i === 0 ? '#f59e0b' : i === parts.length - 1 ? '#f87171' : '#94a3b8',
                    background: i === 0
                      ? 'rgba(245,158,11,0.1)' : i === parts.length - 1
                      ? 'rgba(248,113,113,0.1)' : 'rgba(148,163,184,0.08)',
                    border: `1px solid ${i === 0 ? 'rgba(245,158,11,0.25)' : i === parts.length - 1 ? 'rgba(248,113,113,0.25)' : 'rgba(148,163,184,0.15)'}`,
                    borderRadius: 4, padding: '2px 7px',
                  }}>
                    {part.trim()}
                  </span>
                  {i < parts.length - 1 && (
                    <span style={{ color: '#374151', fontSize: 11, fontWeight: 700 }}>→</span>
                  )}
                </span>
              ))}
            </div>
          </div>
        )
      })()}

      {/* ── Risk + Confidence scores ── */}
      <div style={{ padding: '10px 14px', borderBottom: '1px solid #1a2332' }}>
        <div className="section-title" style={{ marginBottom: 8 }}>Scores</div>

        {/* Risk */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase',
              letterSpacing: '0.08em' }}>Risk Score</span>
            <span className="font-mono" style={{ fontSize: 12, fontWeight: 600, color: riskColor }}>
              {risk}/100
            </span>
          </div>
          <ScoreBar value={risk} colorClass={riskBarClass} />
        </div>

        {/* Confidence */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase',
              letterSpacing: '0.08em' }}>Confidence</span>
            <span className="font-mono" style={{ fontSize: 12, fontWeight: 600, color: '#93c5fd' }}>
              {conf}%
            </span>
          </div>
          <ScoreBar value={conf} colorClass="bar-low" />
        </div>
      </div>

      {/* ── Attack chain ── */}
      {stages.length > 0 && (
        <div style={{ padding: '10px 14px', borderBottom: '1px solid #1a2332' }}>
          <div className="section-title" style={{ marginBottom: 8 }}>Attack Chain</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginBottom: 10 }}>
            {stages.map((stage, i) => (
              <span key={stage} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span className={`chain-stage ${CHAIN_CLASS[stage] || ''}`}>{stage}</span>
                {i < stages.length - 1 && (
                  <span style={{ color: '#374151', fontSize: 12 }}>→</span>
                )}
              </span>
            ))}
          </div>
          {stages.map(stage => stageReason[stage] && (
            <div key={stage} style={{ display: 'flex', gap: 8, marginBottom: 5 }}>
              <span style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase',
                width: 90, flexShrink: 0, paddingTop: 1 }}>{stage}</span>
              <span style={{ fontSize: 11, color: '#9ca3af', lineHeight: 1.5 }}>
                {stageReason[stage]}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* ── Timeline ── */}
      {timeline.length > 0 && (
        <div style={{ padding: '10px 14px', borderBottom: '1px solid #1a2332' }}>
          <div className="section-title" style={{ marginBottom: 6 }}>
            Timeline ({timeline.length} events)
          </div>
          {timeline.map((item, i) => (
            <div key={i} className="timeline-item">
              <div className="timeline-dot">
                <div
                  className={SEV_BAR[item.severity] || 'bar-info'}
                  style={{ width: 7, height: 7, borderRadius: '50%', margin: 'auto', marginTop: 2 }}
                />
              </div>
              <div style={{ flex: 1, paddingBottom: 2 }}>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center',
                  marginBottom: 2, flexWrap: 'wrap' }}>
                  <span className={`badge ${SEV_BADGE[item.severity] || 'badge-info'}`}
                    style={{ fontSize: 9 }}>{item.severity}</span>
                  {item.log_type && (
                    <span style={{ fontSize: 10, color: '#4b5563' }}>{item.log_type}</span>
                  )}
                  {item.time && (
                    <span className="font-mono" style={{ fontSize: 10, color: '#374151',
                      marginLeft: 'auto' }}>{item.time}</span>
                  )}
                </div>
                <span style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>
                  {item.event}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Recommended actions ── */}
      {recs.length > 0 && (
        <div style={{ padding: '10px 14px' }}>
          <div className="section-title" style={{ marginBottom: 6 }}>Recommended Actions</div>
          {recs.map((r, i) => {
            const urgCls = {
              CRITICAL: 'badge-critical',
              HIGH:     'badge-high',
              MEDIUM:   'badge-medium',
              INFO:     'badge-info',
            }[r.urgency] || 'badge-info'
            return (
              <div key={i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 8,
                padding: '6px 0',
                borderBottom: i < recs.length - 1 ? '1px solid #1a2332' : 'none',
              }}>
                <span style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>{r.icon || '→'}</span>
                <span style={{ fontSize: 11.5, color: '#cbd5e1', flex: 1, lineHeight: 1.55 }}>
                  {r.action}
                </span>
                {r.urgency && r.urgency !== 'INFO' && (
                  <span className={`badge ${urgCls}`} style={{ fontSize: 9, flexShrink: 0 }}>
                    {r.urgency}
                  </span>
                )}
              </div>
            )
          })}
        </div>
      )}

    </div>
  )
}
