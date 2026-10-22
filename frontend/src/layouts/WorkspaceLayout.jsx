import { Suspense, useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { Activity, AlertTriangle, Bell, Boxes, Braces, ChartNoAxesCombined, ChevronRight, CircleGauge,
  FlaskConical, GitBranch, LayoutDashboard, LogOut, Menu, Network, PanelLeftClose, PanelLeftOpen,
  Search, Settings, ShieldCheck, X } from 'lucide-react'
import Brand from '../components/Brand'
import { ErrorBoundary, FullLoading } from '../components/UI'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'

const primary = [
  ['Overview', '/dashboard', LayoutDashboard], ['Discovery', '/discovery', Search], ['Crypto Inventory', '/inventory', Boxes],
  ['CBOM', '/cbom', Braces], ['Risk Assessment', '/risk', ShieldCheck], ['PQC Comparison', '/comparison', ChartNoAxesCombined],
  ['Dependencies', '/architecture', Network], ['Monitoring', '/monitoring', Activity], ['Migration', '/migration', GitBranch],
  ['Benchmarks', '/benchmarks', FlaskConical], ['Reports', '/reports', CircleGauge], ['Alerts', '/alerts', AlertTriangle],
]
const secondary = [['Settings', '/settings', Settings]]

function readCollapsed() {
  try { return localStorage.getItem('qsamp_sidebar') === 'collapsed' } catch { return false }
}

export default function WorkspaceLayout() {
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [palette, setPalette] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [cursor, setCursor] = useState(0)
  const { profile, logout, switchOrganization } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const orgId = profile?.active_organization?.id

  useEffect(() => {
    try { localStorage.setItem('qsamp_sidebar', collapsed ? 'collapsed' : 'expanded') } catch { /* storage unavailable */ }
  }, [collapsed])
  useEffect(() => {
    const handler = (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(true) } }
    window.addEventListener('keydown', handler); return () => window.removeEventListener('keydown', handler)
  }, [])
  useEffect(() => {
    if (query.length < 2) { setResults([]); return undefined }
    const controller = new AbortController()
    const timer = setTimeout(() => api.get('/search/', { params: { q: query }, signal: controller.signal })
      .then(r => { setResults(r.data); setCursor(0) }).catch(() => { if (!controller.signal.aborted) setResults([]) }), 250)
    return () => { clearTimeout(timer); controller.abort() }
  }, [query])

  const closePalette = () => { setPalette(false); setQuery(''); setResults([]) }
  const openResult = (item) => { navigate(`/inventory?asset=${item.id}`); closePalette() }
  const paletteKeys = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); closePalette() }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(c + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setCursor(c => Math.max(c - 1, 0)) }
    else if (e.key === 'Enter' && results[cursor]) { e.preventDefault(); openResult(results[cursor]) }
  }
  const changeOrg = async (id) => { await switchOrganization(id); navigate('/dashboard') }

  const nav = (items) => items.map(([label, to, Icon]) => <NavLink key={to} to={to} onClick={() => setMobileOpen(false)} title={collapsed ? label : undefined}>
    <Icon size={18} /><span>{label}</span>
  </NavLink>)
  const signOut = () => { logout(); navigate('/login') }
  const orgs = profile?.organizations || []
  return <div className={`workspace ${collapsed ? 'sidebar-collapsed' : ''}`}>
    <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand"><Brand compact={collapsed} /><button className="icon-button mobile-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X /></button></div>
      <nav aria-label="Workspace">{nav(primary)}<div className="nav-divider" />{nav(secondary)}</nav>
      <button className="collapse-button" onClick={() => setCollapsed(v => !v)} aria-expanded={!collapsed} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>{collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}<span>Collapse</span></button>
    </aside>
    <div className="workspace-main">
      <header className="topbar">
        <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu /></button>
        <div className="org-context"><span className="status-dot" /><div>
          {orgs.length > 1
            ? <select className="org-switcher" aria-label="Active organization" value={orgId || ''} onChange={e => changeOrg(e.target.value)}>{orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}</select>
            : <strong>{profile?.active_organization?.name}</strong>}
          <small>{profile?.active_organization?.is_demo ? 'Demo environment' : 'Local workspace'} - {profile?.active_organization?.role}</small></div></div>
        <button className="command-trigger" onClick={() => setPalette(true)}><Search size={16} /><span>Search assets</span><kbd>Ctrl K</kbd></button>
        <div className="top-actions"><button className="icon-button" onClick={() => navigate('/alerts')} aria-label="Alerts"><Bell /></button><div className="avatar" aria-hidden="true">{profile?.user?.full_name?.split(' ').map(v => v[0]).join('').slice(0, 2) || 'U'}</div><button className="icon-button" onClick={signOut} aria-label="Sign out"><LogOut /></button></div>
      </header>
      {/* Keyed by organization so every page refetches after an org switch; the
          boundary resets when the route changes. */}
      <ErrorBoundary key={orgId} resetKey={location.pathname}>
        <Suspense fallback={<FullLoading label="Loading workspace..." />}><Outlet /></Suspense>
      </ErrorBoundary>
    </div>
    <AnimatePresence>{palette && <motion.div className="modal-layer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={closePalette}>
      <motion.div className="command-palette" role="dialog" aria-label="Search assets" initial={{ scale: .97, y: -12 }} animate={{ scale: 1, y: 0 }} onMouseDown={e => e.stopPropagation()}>
        <div className="command-input"><Search /><input autoFocus value={query} onChange={e => setQuery(e.target.value)} onKeyDown={paletteKeys} placeholder="Search RSA-2048, payments-api, critical..." aria-label="Search assets" aria-controls="command-results" /><button onClick={closePalette} aria-label="Close search"><X /></button></div>
        <div className="command-results" id="command-results" role="listbox">{results.map((item, i) => <button key={item.id} role="option" aria-selected={i === cursor} className={i === cursor ? 'active' : ''} onMouseEnter={() => setCursor(i)} onClick={() => openResult(item)}><Boxes /><span><strong>{item.title}</strong><small>{item.subtitle}</small></span><ChevronRight className="result-arrow" /></button>)}{query.length >= 2 && !results.length && <p>No matching assets.</p>}</div>
      </motion.div>
    </motion.div>}</AnimatePresence>
  </div>
}
