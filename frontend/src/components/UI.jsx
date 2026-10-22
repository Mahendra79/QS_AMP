import { Component } from 'react'
import { motion } from 'framer-motion'
import { AlertTriangle, ArrowUpRight, ChevronLeft, ChevronRight, Database, Inbox, LoaderCircle } from 'lucide-react'

export function Page({ children, className = '' }) {
  return <motion.main className={`page ${className}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: .22 }}>{children}</motion.main>
}

export function PageHeader({ eyebrow, title, description, actions }) {
  return <header className="page-header"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h1>{title}</h1>{description && <p>{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</header>
}

export function MetricCard({ label, value, detail, icon: Icon = Database, tone = 'blue' }) {
  return <motion.article className={`metric-card tone-${tone}`} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
    <div className="metric-icon"><Icon size={18} /></div><div className="metric-value">{value}</div><div className="metric-label">{label}</div>{detail && <div className="metric-detail">{detail}</div>}
  </motion.article>
}

export function Badge({ children, tone }) {
  const resolved = tone || String(children || '').toLowerCase().replaceAll(' ', '-')
  return <span className={`badge badge-${resolved}`}>{children}</span>
}

const QUANTUM_STATES = {
  vulnerable: ['Migration required', 'Public-key cryptography', 'danger'],
  weak_classical: ['Replace now', 'Classically weak', 'danger'],
  protocol_dependent: ['Review protocol', 'Depends on negotiation', 'warning'],
  symmetric_review: ['Review key size', 'Symmetric cryptography', 'warning'],
  hash_review: ['Review usage', 'Hash function', 'review'],
  adequate: ['No PQ change', 'Quantum-resilient use', 'safe'],
  pq_hybrid: ['Hybrid PQC', 'Classical + ML-KEM', 'safe'],
  pq_standardized: ['Post-quantum', 'Standardized algorithm', 'safe'],
  unknown: ['Needs review', 'Posture not determined', 'neutral'],
}

export function RiskStatus({ level = 'safe', score }) {
  return <span className={`status-readout status-${level}`}><i /><span><strong>{level}</strong>{Number.isFinite(score) && <small>{score}/100 overall risk</small>}</span></span>
}

export function QuantumStatus({ status = 'unknown' }) {
  const [label, detail, tone] = QUANTUM_STATES[status] || QUANTUM_STATES.unknown
  return <span className={`status-readout status-${tone}`}><i /><span><strong>{label}</strong><small>{detail}</small></span></span>
}

export function Panel({ title, subtitle, action, children, className = '' }) {
  return <section className={`panel ${className}`}><div className="panel-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>
}

export function EmptyState({ title = 'Nothing here yet', text, action }) {
  return <div className="empty-state"><span><Inbox size={25} /></span><h3>{title}</h3>{text && <p>{text}</p>}{action}</div>
}

export function Loading({ rows = 4 }) {
  return <div className="skeleton-stack" aria-label="Loading">{Array.from({ length: rows }, (_, i) => <div className="skeleton" key={i} />)}</div>
}

export function FullLoading({ label = 'Loading security data...' }) {
  return <div className="center-state"><LoaderCircle className="spin" /><span>{label}</span></div>
}

export function ErrorState({ message }) {
  return <div className="error-state"><AlertTriangle size={18} /><span>{message}</span></div>
}

export function RiskRing({ value = 0, label = 'Quantum Risk' }) {
  const color = value >= 80 ? '#ff4d6d' : value >= 60 ? '#ff9850' : value >= 30 ? '#f0c94d' : '#37d6a0'
  return <div className="risk-ring" style={{ '--score': `${value * 3.6}deg`, '--ring': color }}>
    <div><small>{label}</small><strong>{value}<em>/100</em></strong><Badge tone={value >= 80 ? 'critical' : value >= 60 ? 'high' : value >= 30 ? 'medium' : 'safe'}>{value >= 80 ? 'Critical' : value >= 60 ? 'High' : value >= 30 ? 'Medium' : 'Low'}</Badge></div>
  </div>
}

export function DataTable({ columns, rows, onRowClick, empty }) {
  if (!rows?.length) return empty || <EmptyState />
  // Clickable rows are focusable and open with Enter/Space, not only with a mouse.
  const rowProps = row => onRowClick ? {
    onClick: () => onRowClick(row), tabIndex: 0, className: 'clickable',
    onKeyDown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(row) } },
  } : {}
  return <div className="table-wrap"><table><thead><tr>{columns.map(c => <th key={c.key}>{c.label}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={row.id || i} {...rowProps(row)}>{columns.map(c => <td key={c.key} data-label={c.label}>{c.render ? c.render(row[c.key], row) : row[c.key]}</td>)}</tr>)}</tbody></table></div>
}

// Page controls for DRF page-number pagination ({count, next, previous, results}).
export function Pager({ data, page, setPage, pageSize = 25 }) {
  const count = data?.count || 0
  const pages = Math.max(1, Math.ceil(count / pageSize))
  if (count <= pageSize) return null
  return <nav className="pager" aria-label="Pagination">
    <button className="icon-button" onClick={() => setPage(page - 1)} disabled={!data?.previous} aria-label="Previous page"><ChevronLeft /></button>
    <span>Page {page} of {pages} <small>({count.toLocaleString()} total)</small></span>
    <button className="icon-button" onClick={() => setPage(page + 1)} disabled={!data?.next} aria-label="Next page"><ChevronRight /></button>
  </nav>
}

export function Button({ children, variant = 'primary', icon: Icon, ...props }) {
  return <button className={`button button-${variant}`} {...props}>{Icon && <Icon size={16} />}{children}</button>
}

// Icon-only buttons need an accessible name; `label` is used for both aria-label and tooltip.
export function IconButton({ icon: Icon, label, className = '', ...props }) {
  return <button className={`icon-button ${className}`} aria-label={label} title={label} {...props}><Icon /></button>
}

export class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(error) { return { error } }
  componentDidUpdate(prev) { if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null }) }
  render() {
    if (!this.state.error) return this.props.children
    // A failed lazy chunk after a redeploy is the common cause; reloading fetches the new build.
    return <div className="center-state" role="alert"><AlertTriangle /><span>This page could not be loaded.</span>
      <Button onClick={() => window.location.reload()}>Reload</Button></div>
  }
}

export function LinkButton({ children, ...props }) {
  return <button className="link-button" {...props}>{children}<ArrowUpRight size={14} /></button>
}
