export default function ErrorScreen({ error, onRetry }) {
  const isTimeout   = error?.includes('timed out')
  const isServerDown = error?.includes('fetch') || error?.includes('NetworkError') || error?.includes('Failed to fetch')

  return (
    <div className="glass rounded-3xl border border-red-500/30 p-6 animate-fadeIn">
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-2xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-xl flex-shrink-0">
          {isServerDown ? '🔌' : isTimeout ? '⏰' : '⚠'}
        </div>
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-red-400 mb-1">
            {isServerDown ? 'Cannot reach backend' : isTimeout ? 'Request timed out' : 'Something went wrong'}
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed mb-1">
            {isServerDown
              ? 'Make sure the FastAPI server is running on http://127.0.0.1:8000'
              : isTimeout
              ? 'The request took too long. The LLM may be slow — try again.'
              : error}
          </p>
          {isServerDown && (
            <code className="block mt-2 text-xs text-emerald-400 bg-slate-900/60 rounded-lg px-3 py-2 border border-slate-700/40">
              uvicorn app:app --host 0.0.0.0 --port 8000 --reload
            </code>
          )}
        </div>
      </div>
      <button
        onClick={onRetry}
        className="mt-4 w-full py-2.5 rounded-xl border border-red-500/30 text-red-400 text-sm
                   hover:bg-red-500/10 hover:border-red-400/50 transition-all duration-200"
      >
        ↺ Retry
      </button>
    </div>
  )
}
