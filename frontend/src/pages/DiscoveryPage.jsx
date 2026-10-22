import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Radar, RefreshCw, Trash2 } from 'lucide-react'
import api, { apiError, listData } from '../api/client'
import { Badge, Button, DataTable, EmptyState, ErrorState, IconButton, Loading, Page, PageHeader, Pager, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi, usePolling } from '../hooks/useApi'

export default function DiscoveryPage() {
  const [sourcePage, setSourcePage] = useState(1)
  const [scanPage, setScanPage] = useState(1)
  const sources = useApi(`/discovery/sources/?page=${sourcePage}`)
  const scans = useApi(`/discovery/scans/?page=${scanPage}`)
  const [toast, setToast] = useState(null)
  const { canWrite } = useRole()
  const navigate = useNavigate()
  const sourceRows = listData(sources.data)
  // Keep status and progress current while any scan on screen is still running.
  const active = sourceRows.some(s => s.status === 'scanning') ||
    listData(scans.data).some(s => s.status === 'queued' || s.status === 'running')
  usePolling(sources.reload, active)
  usePolling(scans.reload, active)
  const run = async (id) => { try { await api.post(`/discovery/sources/${id}/scan/`); setToast({ message: 'Discovery scan started.' }); sources.reload({ silent: true }); scans.reload({ silent: true }) } catch (e) { setToast({ type: 'error', message: apiError(e) }) } }
  const remove = async (source) => {
    if (!window.confirm(`Delete "${source.name}"? Its ${source.asset_count} discovered asset(s), findings, and scan history will be removed. This cannot be undone.`)) return
    try { await api.delete(`/discovery/sources/${source.id}/`); setToast({ message: 'Source removed.' }); sources.reload(); scans.reload() } catch (e) { setToast({ type: 'error', message: apiError(e) }) }
  }
  return <Page><PageHeader eyebrow="Discovery engine" title="Connected sources" description="Manage cryptographic discovery across applications, domains, repositories, and CBOMs." actions={canWrite && <Button icon={Plus} onClick={() => navigate('/?add=1')}>Add source</Button>} />
    {sources.error && <ErrorState message={sources.error} />}{sources.loading && !sources.data ? <Loading /> : <div className="source-list">{sourceRows.map(source => <article className="connected-source" key={source.id}><div className="source-type"><Radar /></div><div className="source-main"><div><h2>{source.name}</h2><Badge tone="neutral">{source.source_type.replaceAll('_', ' ')}</Badge></div><p>{source.target}</p><div className="source-stats"><span><strong>{source.asset_count}</strong> Assets</span><span><strong>{source.risk_score}</strong> Risk score</span><span><strong>{source.last_scan_at ? new Date(source.last_scan_at).toLocaleString() : 'Never'}</strong> Last scan</span></div></div><div className="source-actions"><Badge>{source.status}</Badge>{canWrite && source.source_type !== 'cbom' && <IconButton icon={RefreshCw} label={`Scan ${source.name} now`} onClick={() => run(source.id)} disabled={source.status === 'scanning'} />}{canWrite && <IconButton icon={Trash2} className="danger" label={`Delete ${source.name}`} onClick={() => remove(source)} />}</div></article>)}{!sourceRows.length && <EmptyState title="No discovery sources" text="Connect a website, public repository, ZIP archive, or CBOM to begin." />}<Pager data={sources.data} page={sourcePage} setPage={setSourcePage} /></div>}
    <Panel title="Scan history" subtitle="Discovery jobs and evidence collection status"><DataTable rows={listData(scans.data)} empty={scans.loading ? <Loading /> : <EmptyState title="No scans yet" />} columns={[{ key: 'source_name', label: 'Source' }, { key: 'created_at', label: 'Started', render: v => new Date(v).toLocaleString() }, { key: 'duration_seconds', label: 'Duration', render: v => v == null ? '-' : `${v}s` }, { key: 'mode', label: 'Evidence', render: v => <Badge tone="neutral">{v}</Badge> }, { key: 'counters', label: 'Assets', render: v => v?.assets || 0 }, { key: 'status', label: 'Status', render: (v, row) => <span title={row.error || undefined}><Badge>{v}</Badge>{v === 'running' && <small className="progress-text"> {row.progress}%</small>}</span> }]} /><Pager data={scans.data} page={scanPage} setPage={setScanPage} /></Panel><Toast toast={toast} clear={() => setToast(null)} /></Page>
}
