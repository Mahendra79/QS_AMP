import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import api from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(Boolean(localStorage.getItem('qsamp_access')))

  const loadProfile = useCallback(async () => {
    if (!localStorage.getItem('qsamp_access')) { setLoading(false); return null }
    try {
      const { data } = await api.get('/auth/me/')
      setProfile(data)
      if (data.active_organization?.id) localStorage.setItem('qsamp_org', data.active_organization.id)
      return data
    } catch {
      localStorage.removeItem('qsamp_access')
      localStorage.removeItem('qsamp_refresh')
      setProfile(null)
      return null
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { loadProfile() }, [loadProfile])
  useEffect(() => {
    const handler = () => { setProfile(null); setLoading(false) }
    window.addEventListener('qsamp:logout', handler)
    return () => window.removeEventListener('qsamp:logout', handler)
  }, [])

  const login = async (username, password, otp = '') => {
    const { data } = await api.post('/auth/login/', { username, password, otp })
    localStorage.removeItem('qsamp_org')
    localStorage.setItem('qsamp_access', data.access)
    localStorage.setItem('qsamp_refresh', data.refresh)
    return loadProfile()
  }
  const register = async (payload) => {
    const { data } = await api.post('/auth/register/', payload)
    localStorage.removeItem('qsamp_org')
    localStorage.setItem('qsamp_access', data.access)
    localStorage.setItem('qsamp_refresh', data.refresh)
    return loadProfile()
  }
  const logout = () => {
    localStorage.removeItem('qsamp_access'); localStorage.removeItem('qsamp_refresh'); localStorage.removeItem('qsamp_org')
    setProfile(null)
  }
  const switchOrganization = async (id) => {
    localStorage.setItem('qsamp_org', id)
    return loadProfile()
  }
  const value = useMemo(() => ({ profile, loading, login, register, logout, switchOrganization, refresh: loadProfile }), [profile, loading, loadProfile])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)

// Mirrors the backend's role rules (organizations/models.py WRITE_ROLES / ADMIN_ROLES)
// so read-only roles are not shown actions that would only return 403.
const WRITE_ROLES = ['owner', 'admin', 'analyst', 'developer']
const ADMIN_ROLES = ['owner', 'admin']

export function useRole() {
  const role = useContext(AuthContext)?.profile?.active_organization?.role || 'viewer'
  return { role, canWrite: WRITE_ROLES.includes(role), isAdmin: ADMIN_ROLES.includes(role) }
}
