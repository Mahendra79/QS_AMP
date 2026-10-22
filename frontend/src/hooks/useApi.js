import { useCallback, useEffect, useRef, useState } from 'react'
import api, { apiError } from '../api/client'

export function useApi(url, initial = null) {
  const [data, setData] = useState(initial)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const controller = useRef(null)
  // Each load cancels the previous one, so a slow response for an old URL
  // (e.g. an earlier search term) can never overwrite a newer result.
  const load = useCallback(async ({ silent = false } = {}) => {
    controller.current?.abort()
    const current = new AbortController()
    controller.current = current
    if (!silent) { setLoading(true); setError('') }
    try {
      const response = await api.get(url, { signal: current.signal })
      setData(response.data)
      if (silent) setError('')
      return response.data
    } catch (err) {
      if (current.signal.aborted) return null
      setError(apiError(err))
      return null
    } finally {
      if (controller.current === current) setLoading(false)
    }
  }, [url])
  useEffect(() => { load(); return () => controller.current?.abort() }, [load])
  return { data, setData, loading, error, reload: load }
}

// Re-fetches silently every `ms` while `active` is true (e.g. a scan or
// benchmark is running) and stops on its own once the work finishes.
export function usePolling(reload, active, ms = 2000) {
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(() => reload({ silent: true }), ms)
    return () => clearInterval(timer)
  }, [reload, active, ms])
}

export function useDebounced(value, ms = 300) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(timer)
  }, [value, ms])
  return debounced
}
