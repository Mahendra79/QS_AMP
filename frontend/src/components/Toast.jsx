import { useEffect, useRef } from 'react'
import { CheckCircle2, X, XCircle } from 'lucide-react'

// Success messages dismiss themselves; errors stay until dismissed so they are not missed.
export default function Toast({ toast, clear }) {
  const clearRef = useRef(clear)
  clearRef.current = clear  // callers pass a new closure each render; the timer must not restart
  useEffect(() => {
    if (!toast || toast.type === 'error') return undefined
    const timer = setTimeout(() => clearRef.current?.(), 6000)
    return () => clearTimeout(timer)
  }, [toast])
  if (!toast) return null
  const isError = toast.type === 'error'
  return <div className={`toast toast-${toast.type || 'success'}`} role={isError ? 'alert' : 'status'}>
    {isError ? <XCircle size={18} /> : <CheckCircle2 size={18} />}
    <span>{toast.message}</span><button onClick={clear} aria-label="Dismiss"><X size={15} /></button>
  </div>
}
