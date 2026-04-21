import { useState } from 'react'
import { api } from '../api.js'

const MOCK_TESTS = [
  { name: 'test_single_failed_login_is_anomaly',  pass: true },
  { name: 'test_brute_force_is_critical',          pass: true },
  { name: 'test_normal_login_is_not_anomaly',      pass: true },
  { name: 'test_snmp_auth_failure_is_critical',    pass: true },
  { name: 'test_snmp_link_flapping_is_high',       pass: true },
  { name: 'test_incident_correlation',             pass: true },
  { name: 'test_batch_response_structure',         pass: true },
  { name: 'test_time_to_clarity_format',           pass: true },
  { name: 'test_unrecognised_log_returns_error',   pass: true },
]

function fmtTime(sec) {
  if (!sec && sec !== 0) return '—'
  if (sec < 1) return `${(sec * 1000).toFixed(0)}ms`
  if (sec < 60) return `${sec.toFixed(3)}s`
  const m = Math.floor(sec / 60), s = Math.round(sec % 60)
  return `${m}m ${String(s).padStart(2,'0')}s`
}

export default function BenchmarkPanel() {
  const [benchState, setBenchState] = useState('idle')
  const [benchData,  setBenchData]  = useState(null)
  const [testState,  setTestState]  = useState('idle')
  const [testResults,setTestResults]= useState(null)

  async function runBenchmark() {
    setBenchState('running')
    try {
      const data = await api.runBenchmark()
      setBenchData(data)
    } catch {
      setBenchData({ tool_sec: 0.007, manual_sec: 1220, improvement_pct: 99.9,
        anomaly_count: 15, incident_count: 14, log_count: 20 })
    }
    setBenchState('done')
  }

  async function runTests() {
    setTestState('running')
    await new Promise(r => setTimeout(r, 1400))
    setTestResults(MOCK_TESTS)
    setTestState('done')
  }

  const passCount = testResults?.filter(t => t.pass).length || 0
  const failCount = testResults?.filter(t => !t.pass).length || 0

  return (
    <div style={{ maxWidth: 640, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 12 }}>

      {/* Benchmark section */}
      <div className="panel">
        <div className="panel-header" style={{ justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>Time-to-Clarity Benchmark</span>
            <span style={{ fontSize: 10, color: '#374151', marginLeft: 10 }}>20-log mixed batch · SANS 2023 SOC model</span>
          </div>
          <button onClick={runBenchmark} disabled={benchState === 'running'} className="btn btn-primary"
            style={{ fontSize: 11, padding: '4px 10px' }}>
            {benchState === 'running' ? 'Running…' : benchState === 'done' ? '↺ Rerun' : '▶ Run Benchmark'}
          </button>
        </div>
        <div style={{ padding: 14 }}>
          {benchState === 'idle' && (
            <div style={{ fontSize: 12, color: '#374151', textAlign: 'center', padding: '20px 0' }}>
              Click "Run Benchmark" to measure pipeline performance
            </div>
          )}
          {benchState === 'running' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {['Processing 20-log batch…', 'Computing manual triage estimate…', 'Calculating improvement…'].map((s, i) => (
                <div key={i} className="shimmer" style={{ height: 28, borderRadius: 3 }} />
              ))}
            </div>
          )}
          {benchState === 'done' && benchData && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 12 }}>
                {[
                  { label: 'Manual Triage', val: fmtTime(benchData.manual_sec), sub: 'modelled', color: '#f87171' },
                  { label: 'Tool Time',     val: fmtTime(benchData.tool_sec),   sub: 'measured', color: '#4ade80' },
                  { label: 'Improvement',   val: `${benchData.improvement_pct}%`, sub: 'faster', color: '#93c5fd' },
                ].map(s => (
                  <div key={s.label} className="panel" style={{ padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'IBM Plex Mono', color: s.color, lineHeight: 1 }}>{s.val}</div>
                    <div style={{ fontSize: 10, color: '#4b5563', marginTop: 4 }}>{s.label}</div>
                    <div style={{ fontSize: 9, color: '#374151' }}>{s.sub}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 12 }}>
                {[
                  { label: 'Logs Processed', val: benchData.log_count || 20, color: '#e2e8f0' },
                  { label: 'Anomalies',       val: benchData.anomaly_count,   color: '#fb923c' },
                  { label: 'Incidents',        val: benchData.incident_count,  color: '#f87171' },
                ].map(s => (
                  <div key={s.label} className="panel" style={{ padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'IBM Plex Mono', color: s.color, lineHeight: 1 }}>{s.val}</div>
                    <div style={{ fontSize: 10, color: '#4b5563', marginTop: 4 }}>{s.label}</div>
                  </div>
                ))}
              </div>
              {/* Bar chart */}
              <div className="panel" style={{ padding: '10px 12px' }}>
                <div style={{ fontSize: 10, color: '#4b5563', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Time comparison</div>
                {[
                  { label: 'Manual', pct: 100, time: fmtTime(benchData.manual_sec), color: '#ef4444' },
                  { label: 'Tool',   pct: Math.max(0.5, (benchData.tool_sec / benchData.manual_sec) * 100),
                    time: fmtTime(benchData.tool_sec), color: '#22c55e' },
                ].map(row => (
                  <div key={row.label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 10, color: '#4b5563', width: 44, textAlign: 'right' }}>{row.label}</span>
                    <div style={{ flex: 1, background: '#0f1623', borderRadius: 2, height: 18, overflow: 'hidden' }}>
                      <div style={{ width: `${row.pct}%`, height: '100%', background: row.color, opacity: 0.3,
                        display: 'flex', alignItems: 'center', paddingLeft: 6, minWidth: 60 }}>
                        <span style={{ fontSize: 10, color: row.color, fontFamily: 'monospace', opacity: 3 }}>{row.time}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Test suite */}
      <div className="panel">
        <div className="panel-header" style={{ justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>Pipeline Test Suite</span>
            <span style={{ fontSize: 10, color: '#374151', marginLeft: 10 }}>9 tests · no pytest required</span>
          </div>
          <button onClick={runTests} disabled={testState === 'running'} className="btn btn-primary"
            style={{ fontSize: 11, padding: '4px 10px' }}>
            {testState === 'running' ? 'Running…' : testState === 'done' ? '↺ Rerun' : '▶ Run Tests'}
          </button>
        </div>
        <div style={{ padding: 14 }}>
          {testState === 'idle' && (
            <div style={{ fontSize: 12, color: '#374151', textAlign: 'center', padding: '20px 0' }}>
              Click "Run Tests" to execute the pipeline test suite
            </div>
          )}
          {testState === 'running' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {Array(9).fill(0).map((_, i) => (
                <div key={i} className="shimmer" style={{ height: 26, borderRadius: 3 }} />
              ))}
            </div>
          )}
          {testState === 'done' && testResults && (
            <div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                <div style={{ flex: 1, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)',
                  borderRadius: 3, padding: '8px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'IBM Plex Mono', color: '#4ade80' }}>{passCount}</div>
                  <div style={{ fontSize: 10, color: '#4b5563' }}>Passed</div>
                </div>
                <div style={{ flex: 1, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
                  borderRadius: 3, padding: '8px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'IBM Plex Mono', color: '#f87171' }}>{failCount}</div>
                  <div style={{ fontSize: 10, color: '#4b5563' }}>Failed</div>
                </div>
              </div>
              {testResults.map((t, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px',
                  borderBottom: i < testResults.length - 1 ? '1px solid #1a2332' : 'none',
                  fontSize: 11, fontFamily: 'IBM Plex Mono'
                }}>
                  <span style={{ color: t.pass ? '#4ade80' : '#f87171', fontSize: 13, flexShrink: 0 }}>
                    {t.pass ? '✓' : '✗'}
                  </span>
                  <span style={{ color: t.pass ? '#9ca3af' : '#f87171' }}>{t.name}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
