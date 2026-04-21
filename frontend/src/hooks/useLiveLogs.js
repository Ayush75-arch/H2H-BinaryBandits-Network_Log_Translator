import { useState, useCallback, useRef, useEffect } from 'react'
import { startLogStream } from '../api.js'

/**
 * useLiveLogs — manages real-time log streaming state
 *
 * Returns:
 *   isLive         — boolean, streaming active
 *   logs           — array of processed log entries (grows as stream arrives)
 *   incidents      — latest incident list
 *   stats          — { total_processed, anomaly_count, incident_count, top_severity }
 *   newIncidentIPs — set of IPs that just became incidents (cleared after 3s)
 *   compromiseAlerts — array of { ip, message } recently detected
 *   streamDone     — boolean, stream completed
 *   startStream(logsArray, delayMs) — begin streaming
 *   stopStream()   — abort stream
 *   resetStream()  — clear all state
 */
export function useLiveLogs() {
  const [isLive,            setIsLive]            = useState(false)
  const [logs,              setLogs]              = useState([])
  const [incidents,         setIncidents]         = useState([])
  const [stats,             setStats]             = useState(null)
  const [newIncidentIPs,    setNewIncidentIPs]    = useState(new Set())
  const [compromiseAlerts,  setCompromiseAlerts]  = useState([])
  const [streamDone,        setStreamDone]        = useState(false)
  const [streamError,       setStreamError]       = useState(null)
  const [totalLogs,         setTotalLogs]         = useState(0)
  const [recommendedActions, setRecommendedActions] = useState([])

  const streamRef     = useRef(null)
  const newIPTimerRef = useRef(null)

  const stopStream = useCallback(() => {
    streamRef.current?.stop()
    streamRef.current = null
    setIsLive(false)
  }, [])

  const resetStream = useCallback(() => {
    stopStream()
    setLogs([])
    setIncidents([])
    setStats(null)
    setNewIncidentIPs(new Set())
    setCompromiseAlerts([])
    setStreamDone(false)
    setStreamError(null)
    setTotalLogs(0)
    setRecommendedActions([])
  }, [stopStream])

  const startStream = useCallback((logsArray, delayMs = 450) => {
    resetStream()
    setIsLive(true)
    setStreamDone(false)

    streamRef.current = startLogStream({
      logs: logsArray,
      delayMs,

      onStart: ({ total_logs }) => {
        setTotalLogs(total_logs)
      },

      onLog: (entry) => {
        // Capture a stable ID at the time the log arrives, then clear _isNew after animation
        const entryId = `${entry.index}-${Date.now()}`
        setLogs(prev => [...prev, { ...entry, _isNew: true, _id: entryId }])
        if (entry.stats) setStats(entry.stats)
        setTimeout(() => {
          setLogs(prev => prev.map(l => l._id === entryId ? { ...l, _isNew: false } : l))
        }, 600)
      },

      onIncidentUpdate: ({ incidents: newInc, new_ips, stats: newStats }) => {
        setIncidents(newInc)
        if (newStats) setStats(newStats)
        if (new_ips?.length) {
          setNewIncidentIPs(prev => new Set([...prev, ...new_ips]))
          clearTimeout(newIPTimerRef.current)
          newIPTimerRef.current = setTimeout(() => setNewIncidentIPs(new Set()), 4000)
        }
      },

      onCompromiseAlert: (alert) => {
        setCompromiseAlerts(prev => [{ ...alert, _id: Date.now() }, ...prev.slice(0, 2)])
        setTimeout(() => {
          setCompromiseAlerts(prev => prev.filter(a => a._id !== alert._id))
        }, 6000)
      },

      onComplete: (data) => {
        setStreamDone(true)
        setIsLive(false)
        if (data.incidents)           setIncidents(data.incidents)
        if (data.recommended_actions) setRecommendedActions(data.recommended_actions)
        setStats({
          total_processed: data.total,
          anomaly_count:   data.anomaly_count,
          incident_count:  data.incident_count,
          top_severity:    data.top_severity,
        })
      },

      onError: (msg) => {
        setStreamError(msg)
        setIsLive(false)
      },
    })
  }, [resetStream])

  // Cleanup on unmount
  useEffect(() => () => stopStream(), [stopStream])

  return {
    isLive, logs, incidents, stats, newIncidentIPs,
    compromiseAlerts, streamDone, streamError,
    totalLogs, recommendedActions,
    startStream, stopStream, resetStream,
  }
}
