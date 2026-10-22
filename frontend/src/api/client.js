import axios from 'axios'

const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('qsamp_access')
  const org = localStorage.getItem('qsamp_org')
  if (token) config.headers.Authorization = `Bearer ${token}`
  if (org) config.headers['X-Organization'] = org
  return config
})

// One refresh at a time: when several requests expire together they all wait on
// the same call. Refresh tokens rotate, so the replacement must be stored too -
// otherwise the session ends when the original refresh token expires.
let refreshing = null

function refreshAccessToken() {
  if (!refreshing) {
    const refresh = localStorage.getItem('qsamp_refresh')
    refreshing = axios.post(`${api.defaults.baseURL}/auth/refresh/`, { refresh })
      .then(({ data }) => {
        localStorage.setItem('qsamp_access', data.access)
        if (data.refresh) localStorage.setItem('qsamp_refresh', data.refresh)
        return data.access
      })
      .finally(() => { refreshing = null })
  }
  return refreshing
}

api.interceptors.response.use((response) => response, async (error) => {
  const original = error.config
  const refresh = localStorage.getItem('qsamp_refresh')
  if (error.response?.status === 401 && refresh && !original?._retry && !original?.url?.includes('/auth/')) {
    original._retry = true
    try {
      const access = await refreshAccessToken()
      original.headers.Authorization = `Bearer ${access}`
      return api(original)
    } catch {
      localStorage.removeItem('qsamp_access')
      localStorage.removeItem('qsamp_refresh')
      localStorage.removeItem('qsamp_org')
      window.dispatchEvent(new Event('qsamp:logout'))
    }
  }
  return Promise.reject(error)
})

export const apiErrorCode = (error) => error.response?.data?.error?.code || ''

export const apiError = (error) => error.response?.data?.error?.message ||
  Object.values(error.response?.data || {})?.flat()?.[0] || error.message || 'Something went wrong.'

export const listData = (data) => Array.isArray(data) ? data : (data?.results || [])

export async function downloadFile(url, filename) {
  const response = await api.get(url, { responseType: 'blob' })
  const href = URL.createObjectURL(response.data)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(href)
}

export default api
