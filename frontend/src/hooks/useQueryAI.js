import { useState, useCallback } from 'react'
import { api } from '../api.js'

export const QUERY_SUGGESTIONS = [
  "Was there a breach?",
  "Which IP is most dangerous?",
  "Explain the attack",
  "What should I do next?",
  "How many incidents were detected?",
  "Summarize what happened",
]

/**
 * useQueryAI — manages NL query state
 *
 * Changes from v8:
 *   - `ask(question, context)` still accepts context but it is now optional.
 *     When the caller passes an empty object {} the backend will auto-resolve
 *     context from its in-memory LAST_CONTEXT store — no more "No analysis
 *     data available yet" when the user forgot to pass context.
 *   - Error messages are more informative (include HTTP status when available).
 *
 * Returns:
 *   messages        — chat history [{ role, text, incident, confidence, ts }]
 *   isThinking      — boolean, query in flight
 *   ask(q, ctx?)    — send a question; ctx defaults to {}
 *   clearChat()     — reset chat history
 */
export function useQueryAI() {
  const [messages,   setMessages]   = useState([])
  const [isThinking, setIsThinking] = useState(false)

  const ask = useCallback(async (question, context = {}) => {
    if (!question.trim()) return

    const userMsg = { role: 'user', text: question, ts: Date.now() }
    setMessages(prev => [...prev, userMsg])
    setIsThinking(true)

    try {
      // Pass whatever context we have; backend falls back to LAST_CONTEXT
      // automatically when context is empty.
      const result = await api.query(question, context)

      setMessages(prev => [...prev, {
        role:       'assistant',
        text:       result.answer,
        confidence: result.confidence ?? 0,
        incident:   result.related_incident ?? null,
        ts:         Date.now(),
      }])
    } catch (err) {
      const errText = err.message?.includes('Failed to fetch')
        ? 'Cannot reach backend — is the server running on port 8000?'
        : `Error: ${err.message || 'Query failed'}`

      setMessages(prev => [...prev, {
        role:       'assistant',
        text:       errText,
        confidence: 0,
        incident:   null,
        ts:         Date.now(),
      }])
    } finally {
      setIsThinking(false)
    }
  }, [])

  const clearChat = useCallback(() => setMessages([]), [])

  return { messages, isThinking, ask, clearChat }
}
