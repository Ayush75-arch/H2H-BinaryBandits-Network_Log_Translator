/**
 * QueryPanel.jsx
 *
 * Analyst query bar at the bottom of the SOC dashboard.
 *
 * CRITICAL: Always passes context from useLiveLogs to ask():
 *   ask(question, { logs, incidents, stats })
 *
 * Never calls ask(question) without context.
 * Context is pulled directly from this component via props (logs, incidents, stats).
 */

import { useState, useRef, useEffect } from 'react'
import { api } from '../api.js'
import { useQueryAI, QUERY_SUGGESTIONS } from '../hooks/useQueryAI.js'

export default function QueryPanel({ logs, incidents, stats, recommendedActions }) {
  const [input,    setInput]    = useState('')
  const [expanded, setExpanded] = useState(false)
  const [backendHasCtx, setBackendHasCtx] = useState(null)
  const { messages, isThinking, ask, clearChat } = useQueryAI()
  const inputRef = useRef(null)

  // Check on mount whether backend already has stored context
  useEffect(() => {
    api.getContext()
      .then(d => setBackendHasCtx(d?.available === true))
      .catch(() => setBackendHasCtx(false))
  }, [])

  // Once local data arrives, context is available
  useEffect(() => {
    if (logs?.length || incidents?.length) {
      setBackendHasCtx(true)
    }
  }, [logs, incidents])

  const hasLocalCtx = !!(logs?.length || incidents?.length)
  const hasAnyCtx   = hasLocalCtx || backendHasCtx === true

  const ctxLabel =
    hasLocalCtx           ? `Context: ${logs?.length ?? 0} logs, ${incidents?.length ?? 0} incidents` :
    backendHasCtx === true  ? 'Backend context available' :
    backendHasCtx === null  ? 'Checking…' :
                              'No analysis context — analyze logs first'

  const lastAnswer   = messages.filter(m => m.role === 'assistant').slice(-1)[0]
  const lastQuestion = messages.filter(m => m.role === 'user').slice(-1)[0]
  const answerCount  = messages.filter(m => m.role === 'assistant').length

  function submit(question) {
    const q = typeof question === 'string' ? question.trim() : ''
    if (!q || isThinking) return

    // Strip internal UI fields (_isNew, _id) before sending to backend
    const cleanLogs = (logs || []).map(({ _isNew, _id, ...rest }) => rest)

    // ALWAYS pass full context — backend needs recommended_actions for "what should I do next"
    const context = {
      logs:                cleanLogs,
      incidents:           incidents           || [],
      stats:               stats               || {},
      recommended_actions: recommendedActions  || [],
    }
    ask(q, context)
    setInput('')
    setExpanded(true)
  }

  function handleKey(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      submit(input)
    }
  }

  return (
    <div className="query-panel" style={{ padding: '8px 14px' }}>

      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
          stroke="#4b5563" strokeWidth="2">
          <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
        </svg>
        <span style={{ fontSize: 10, fontWeight: 600, color: '#4b5563',
          textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          Analyst Query
        </span>

        {/* Context status indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 6 }}>
          <span className={`status-dot ${hasAnyCtx ? 'status-online' : 'status-offline'}`} />
          <span style={{ fontSize: 10, color: hasAnyCtx ? '#4ade80' : '#6b7280' }}>
            {ctxLabel}
          </span>
        </div>

        {messages.length > 0 && (
          <button
            onClick={clearChat}
            className="btn"
            style={{ marginLeft: 'auto', fontSize: 10, padding: '2px 7px' }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Input + Ask button */}
      <div style={{ display: 'flex', gap: 6, marginBottom: expanded && lastAnswer ? 8 : 0 }}>
        <input
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={hasAnyCtx
            ? 'Ask about threats, IPs, attack chains, recommendations…'
            : 'Analyze logs first, then ask questions…'}
          disabled={isThinking}
          className="soc-input"
          style={{ flex: 1 }}
        />
        <button
          onClick={() => submit(input)}
          disabled={isThinking || !input.trim()}
          className="btn btn-primary"
          style={{ padding: '6px 14px', flexShrink: 0 }}
        >
          {isThinking
            ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2.5"
                style={{ animation: 'spin 1s linear infinite' }}>
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
              </svg>
            : <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2">
                <path d="M22 2L11 13M22 2L15 22l-4-9-9-4 20-7z"/>
              </svg>
          }
          {isThinking ? 'Querying…' : 'Ask'}
        </button>
      </div>

      {/* Suggestion chips — always visible when not thinking */}
      {!isThinking && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 5 }}>
          {QUERY_SUGGESTIONS.slice(0, 5).map(s => (
            <button
              key={s}
              onClick={(e) => { e.preventDefault(); submit(s) }}
              className="btn"
              style={{ fontSize: 10, padding: '3px 8px', cursor: 'pointer' }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Answer area */}
      {(expanded || isThinking) && (
        <div style={{ marginTop: 8 }}>

          {/* Last question echo */}
          {lastQuestion && (
            <div style={{
              fontSize: 11, color: '#4b5563', marginBottom: 5,
              fontFamily: 'IBM Plex Mono',
              borderLeft: '2px solid #1f2937', paddingLeft: 8,
            }}>
              {lastQuestion.text}
            </div>
          )}

          {/* Loading / answer */}
          {isThinking ? (
            <div className="query-answer" style={{ color: '#374151' }}>
              <span className="blink">▌</span> Analyzing…
            </div>
          ) : lastAnswer ? (
            <div className="query-answer">

              {/* Confidence bar */}
              {lastAnswer.confidence > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <span style={{ fontSize: 10, color: '#4b5563',
                    textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Confidence
                  </span>
                  <div style={{ flex: 1, background: '#1f2937', borderRadius: 2,
                    height: 3, maxWidth: 80 }}>
                    <div style={{
                      width: `${lastAnswer.confidence}%`,
                      height: '100%',
                      borderRadius: 2,
                      background:
                        lastAnswer.confidence >= 85 ? '#4ade80' :
                        lastAnswer.confidence >= 60 ? '#fbbf24' : '#f87171',
                      transition: 'width 0.4s ease',
                    }} />
                  </div>
                  <span className="font-mono" style={{ fontSize: 10, color: '#93c5fd' }}>
                    {lastAnswer.confidence}%
                  </span>
                </div>
              )}

              {/* Answer text */}
              <div style={{ whiteSpace: 'pre-wrap' }}>{lastAnswer.text}</div>

              {/* Related incident */}
              {lastAnswer.incident && (
                <div style={{
                  marginTop: 8, padding: '5px 8px',
                  background: '#0f1623', border: '1px solid #1f2937',
                  borderRadius: 3, display: 'flex', alignItems: 'center',
                  gap: 8, fontSize: 11,
                }}>
                  <span className={`badge badge-${(lastAnswer.incident.severity || 'info').toLowerCase()}`}>
                    {lastAnswer.incident.severity}
                  </span>
                  <span className="code-tag">{lastAnswer.incident.ip}</span>
                  <span style={{ color: '#6b7280' }}>
                    Risk: {lastAnswer.incident.risk_score}/100
                  </span>
                  {lastAnswer.incident.is_compromised && (
                    <span style={{ color: '#f87171', fontWeight: 600, fontSize: 10 }}>
                      ⚠ COMPROMISED
                    </span>
                  )}
                </div>
              )}

              {/* History count / collapse */}
              {answerCount > 1 && (
                <div style={{ marginTop: 6, borderTop: '1px solid #1a2332', paddingTop: 5 }}>
                  <span style={{ fontSize: 10, color: '#4b5563' }}>
                    {answerCount} queries ·{' '}
                    <button
                      onClick={() => setExpanded(false)}
                      style={{ background: 'none', border: 'none', color: '#374151',
                        cursor: 'pointer', fontSize: 10, padding: 0 }}
                    >
                      collapse
                    </button>
                  </span>
                </div>
              )}
            </div>
          ) : null}
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
