import { useState } from 'react'
import { Download, FileBarChart, FileText } from 'lucide-react'
import api, { apiError, downloadFile, listData } from '../api/client'
import { Badge, DataTable, EmptyState, IconButton, Page, PageHeader, Pager, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

const types = [['executive_security', 'Executive Security Report', FileBarChart], ['cryptographic_inventory', 'Cryptographic Inventory', FileText], ['quantum_risk', 'Quantum Risk Report', FileBarChart], ['migration_roadmap', 'Migration Roadmap', FileText]]

const size = bytes => bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`

export default function ReportsPage() {
  const [page, setPage] = useState(1)
  const reports = useApi(`/reports/?page=${page}`)
  const [toast, setToast] = useState(null)
  const [busy, setBusy] = useState('')
  const { canWrite } = useRole()
  const generate = async (report_type, file_format = 'pdf') => {
    setBusy(`${report_type}:${file_format}`)
    try { await api.post('/reports/generate/', { report_type, file_format }); setToast({ message: 'Report generated.' }); setPage(1); reports.reload({ silent: true }) }
    catch (e) { setToast({ type: 'error', message: apiError(e) }) } finally { setBusy('') }
  }
  const download = row => downloadFile(`/reports/${row.id}/download/`, `${row.title}.${row.file_format}`).catch(e => setToast({ type: 'error', message: apiError(e) }))
  return <Page><PageHeader eyebrow="Evidence and communication" title="Reports" description="Generate auditable security, inventory, risk, and migration deliverables." />
    {canWrite && <div className="report-types">{types.map(([key, label, Icon]) => <article key={key}><Icon /><div><h2>{label}</h2><p>Current organization data with clear demo and evidence labels.</p></div><div>{['pdf', 'json', 'csv'].map(fmt => <button key={fmt} disabled={Boolean(busy)} aria-label={`Generate ${label} as ${fmt.toUpperCase()}`} onClick={() => generate(key, fmt)}>{busy === `${key}:${fmt}` ? '...' : fmt.toUpperCase()}</button>)}</div></article>)}</div>}
    <Panel title="Generated reports" subtitle="Secure organization-scoped report archive"><DataTable rows={listData(reports.data)} empty={<EmptyState title="No reports generated yet" />} columns={[{ key: 'title', label: 'Report' }, { key: 'file_format', label: 'Format', render: v => <Badge tone="neutral">{v.toUpperCase()}</Badge> }, { key: 'size_bytes', label: 'Size', render: v => size(v || 0) }, { key: 'created_at', label: 'Generated', render: v => new Date(v).toLocaleString() }, { key: 'download_url', label: '', render: (v, row) => <IconButton icon={Download} label={`Download ${row.title}`} onClick={() => download(row)} /> }]} /><Pager data={reports.data} page={page} setPage={setPage} /></Panel><Toast toast={toast} clear={() => setToast(null)} /></Page>
}
