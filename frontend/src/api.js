const BASE = 'http://127.0.0.1:8000'
const TIMEOUT_MS = 45_000

async function fetchWithTimeout(url, opts = {}) {
  const ctrl = new AbortController()
  const id = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal })
    clearTimeout(id)
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${res.status}`)
    }
    return res.json()
  } catch (err) {
    clearTimeout(id)
    if (err.name === 'AbortError') throw new Error('Request timed out')
    throw err
  }
}

export const api = {
  analyzeSingle: (log) =>
    fetchWithTimeout(`${BASE}/analyze`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log }),
    }),

  analyzeBatch: (logs) =>
    fetchWithTimeout(`${BASE}/analyze/batch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs }),
    }),

  runBenchmark: () =>
    fetchWithTimeout(`${BASE}/benchmark`, { method: 'POST' }),

  health: () =>
    fetchWithTimeout(`${BASE}/`),

  /**
   * Query the analyst chatbot.
   *
   * `context` is now OPTIONAL — when omitted (or empty), the backend
   * automatically falls back to the last persisted LAST_CONTEXT.
   * The frontend still passes context when it has it so the backend
   * can pick the most up-to-date data.
   */
  query: (question, context = {}) =>
    fetchWithTimeout(`${BASE}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, context }),
    }),

  /**
   * GET /context — fetch the last stored analysis context from the backend.
   * Useful for debugging or populating the chatbot status indicator.
   */
  getContext: () =>
    fetchWithTimeout(`${BASE}/context`),
}

export function startLogStream({
  logs, delayMs = 450,
  onLog, onIncidentUpdate, onCompromiseAlert,
  onComplete, onError, onStart,
}) {
  let aborted = false
  let reader  = null

  const run = async () => {
    try {
      const res = await fetch(`${BASE}/stream/logs`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ logs, delay_ms: delayMs }),
      })
      if (!res.ok) throw new Error(`Stream failed: HTTP ${res.status}`)
      reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        if (aborted) break
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()
        let evt = null, dat = null
        for (const line of lines) {
          if      (line.startsWith('event: ')) evt = line.slice(7).trim()
          else if (line.startsWith('data: '))  dat = line.slice(6).trim()
          else if (line === '' && evt && dat) {
            try {
              const p = JSON.parse(dat)
              if (evt === 'stream_start'     && onStart)           onStart(p)
              if (evt === 'log_processed'    && onLog)             onLog(p)
              if (evt === 'incident_update'  && onIncidentUpdate)  onIncidentUpdate(p)
              if (evt === 'compromise_alert' && onCompromiseAlert) onCompromiseAlert(p)
              if (evt === 'stream_complete'  && onComplete)        onComplete(p)
              if (evt === 'error'            && onError)           onError(p.message)
            } catch (_) {}
            evt = null; dat = null
          }
        }
      }
    } catch (err) {
      if (!aborted && onError) onError(err.message)
    }
  }

  run()
  return { stop: () => { aborted = true; reader?.cancel() } }
}
