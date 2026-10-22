import { useEffect, useState } from 'react'
import { Check, CircleCheck, RotateCcw, VolumeX } from 'lucide-react'
import api, { apiError, listData } from '../api/client'
import { Badge, Button, EmptyState, ErrorState, IconButton, Loading, Page, PageHeader, Pager } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

const FILTERS = [
  ['active', 'Active', 'status__in=open,acknowledged'], ['muted', 'Muted', 'status=muted'],
  ['resolved', 'Resolved', 'status=resolved'], ['all', 'All', ''],
]
const EMPTY = {
  active: ['No active alerts', 'Your alert queue is clear.'], muted: ['No muted alerts', ''],
  resolved: ['No resolved alerts', ''], all: ['No alerts yet', 'Alerts appear when scans or monitoring find something that needs an owner.'],
}

export default function AlertsPage() {
  const [filter, setFilter] = useState('active')
  const [page, setPage] = useState(1)
  useEffect(() => { setPage(1) }, [filter])
  const query = FILTERS.find(([key]) => key === filter)[2]
  const alerts = useApi(`/alerts/?page=${page}${query ? `&${query}` : ''}`)
  const [toast, setToast] = useState(null)
  const { canWrite } = useRole()
  const act = async (id, action) => { try { await api.post(`/alerts/${id}/${action}/`); alerts.reload({ silent: true }) } catch (e) { setToast({ type: 'error', message: apiError(e) }) } }
  const rows = listData(alerts.data)
  const [emptyTitle, emptyText] = EMPTY[filter]
  return <Page><PageHeader eyebrow="Security operations" title="Alerts" description="Triage changes and findings that require an owner or a decision."
      actions={<div className="segmented text-tabs" role="tablist" aria-label="Alert status">{FILTERS.map(([key, label]) => <button key={key} role="tab" aria-selected={filter === key} className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>{label}</button>)}</div>} />
    {alerts.error && <ErrorState message={alerts.error} />}{alerts.loading && !alerts.data ? <Loading /> : <div className="alert-list">{rows.map(alert => <article key={alert.id}><i className={`severity-${alert.severity}`} /><div><div><Badge>{alert.severity}</Badge><span className="alert-type">{alert.alert_type.replaceAll('_', ' ')}</span><time>{new Date(alert.created_at).toLocaleString()}</time></div><h2>{alert.title}</h2><p>{alert.message}</p><small>{alert.asset_name || 'Organization-wide'} - {alert.status}</small></div>
      {canWrite && <aside>
        {alert.status === 'open' && <Button variant="secondary" icon={Check} onClick={() => act(alert.id, 'acknowledge')}>Acknowledge</Button>}
        {['open', 'acknowledged'].includes(alert.status) && <Button variant="ghost" icon={CircleCheck} onClick={() => act(alert.id, 'resolve')}>Resolve</Button>}
        {['open', 'acknowledged'].includes(alert.status) && <IconButton icon={VolumeX} label="Mute alert" onClick={() => act(alert.id, 'mute')} />}
        {['resolved', 'muted'].includes(alert.status) && <Button variant="ghost" icon={RotateCcw} onClick={() => act(alert.id, 'reopen')}>Reopen</Button>}
      </aside>}</article>)}{!rows.length && <EmptyState title={emptyTitle} text={emptyText} />}<Pager data={alerts.data} page={page} setPage={setPage} /></div>}<Toast toast={toast} clear={() => setToast(null)} /></Page>
}
