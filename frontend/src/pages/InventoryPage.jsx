import { useEffect, useMemo, useState } from 'react'
import { GitCompareArrows, Search, X } from 'lucide-react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import api, { listData } from '../api/client'
import { Badge, Button, DataTable, EmptyState, ErrorState, IconButton, Loading, Page, PageHeader, Pager, QuantumStatus, RiskStatus } from '../components/UI'
import { useApi, useDebounced } from '../hooks/useApi'

function AssetDrawer({ asset, close, compare }) {
  useEffect(() => {
    if (!asset) return undefined
    const onKey = e => { if (e.key === 'Escape') close() }
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey)
  }, [asset, close])
  if (!asset) return null
  const fields = [['Asset ID', asset.asset_ref || asset.id], ['Application', asset.application], ['Source', asset.source_name], ['Location', asset.source_location], ['Algorithm', asset.algorithm], ['Variant', asset.variant], ['Primitive', asset.primitive], ['Purpose', asset.purpose?.replaceAll('_', ' ')], ['Key size', asset.key_size ? `${asset.key_size} bits` : '-'], ['Library', asset.library], ['Protocol', asset.protocol], ['Evidence', asset.metadata?.evidence_type?.replaceAll('_', ' ')], ['Confidence', asset.metadata?.confidence], ['Key exchange group', asset.metadata?.key_exchange_group], ['Migrated from', asset.metadata?.migrated_from], ['Environment', asset.environment], ['Last detected', new Date(asset.last_seen).toLocaleString()]]
  return <div className="drawer-layer" onMouseDown={close}><aside className="drawer" role="dialog" aria-label={asset.name} onMouseDown={e => e.stopPropagation()}><header><div><span className="eyebrow">Cryptographic asset</span><h2>{asset.name}</h2></div><IconButton icon={X} label="Close details" onClick={close} /></header><div className="drawer-posture"><div><small>Overall risk</small><RiskStatus level={asset.risk_level} score={asset.risk_score} /></div><div><small>Required action</small><QuantumStatus status={asset.quantum_status} /></div></div>{asset.metadata?.requires_verification && <div className="info-note">This record was declared by a completed migration task and will be verified by the next discovery scan.</div>}<dl>{fields.filter(([, value]) => value !== undefined).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || '-'}</dd></div>)}</dl><div className="candidate-list"><h3>PQC candidates</h3>{asset.pqc_candidates?.length ? asset.pqc_candidates.map(v => <Badge key={v} tone="blue">{v}</Badge>) : <p>Run purpose-aware recommendation analysis.</p>}</div><footer><Button icon={GitCompareArrows} onClick={() => compare(asset)}>Compare with PQC</Button></footer></aside></div>
}

export default function InventoryPage() {
  const [params, setParams] = useSearchParams()
  const [query, setQuery] = useState('')
  const [risk, setRisk] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(null)
  const navigate = useNavigate()
  const search = useDebounced(query.trim(), 300)
  useEffect(() => { setPage(1) }, [search, risk])
  const url = useMemo(() => `/inventory/?page=${page}${search ? `&search=${encodeURIComponent(search)}` : ''}${risk ? `&risk_level=${risk}` : ''}`, [search, risk, page])
  const { data, loading, error } = useApi(url)
  useEffect(() => { const id = params.get('asset'); if (id) api.get(`/inventory/${id}/`).then(r => setSelected(r.data)).catch(() => {}) }, [params])
  const rows = listData(data)
  const open = row => { setSelected(row); setParams({ asset: row.id }) }
  const close = () => { setSelected(null); setParams({}) }
  const compare = asset => navigate(`/comparison?asset=${asset.id}`)
  return <Page><PageHeader eyebrow="Cryptographic inventory" title="Crypto assets" description="A searchable record of algorithms, keys, protocols, certificates, and implementation evidence." />
    <div className="filterbar"><label className="search-field"><Search /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search asset, application, algorithm, library..." aria-label="Search assets" /></label><select value={risk} onChange={e => setRisk(e.target.value)} aria-label="Risk level"><option value="">All risk levels</option>{['critical', 'high', 'medium', 'low', 'safe'].map(v => <option key={v}>{v}</option>)}</select><span>{(data?.count ?? rows.length).toLocaleString()} assets</span></div>
    {error && <ErrorState message={error} />}{loading && !data ? <Loading rows={8} /> : <div className={loading ? 'is-refreshing' : ''}><DataTable rows={rows} onRowClick={open} empty={<EmptyState title={search || risk ? 'No assets match these filters' : 'No cryptographic assets discovered yet'} text={search || risk ? 'Try a different search or risk level.' : 'Run a discovery scan or upload a CycloneDX CBOM.'} />} columns={[{ key: 'name', label: 'Asset', render: (v, row) => <span className="table-primary"><strong>{v || row.algorithm}</strong><small>{row.asset_ref}</small></span> }, { key: 'application', label: 'Application', render: (v, row) => <span className="table-primary"><strong>{v || 'Unassigned'}</strong><small>{row.environment || 'Environment unknown'}</small></span> }, { key: 'algorithm', label: 'Usage', render: (v, row) => <span className="table-primary"><strong>{v}</strong><small>{row.purpose?.replaceAll('_', ' ') || 'Purpose unknown'}</small></span> }, { key: 'metadata', label: 'Evidence', render: v => <span className="evidence-value"><strong>{v?.confidence || 'Unknown'}</strong><small>{v?.evidence_type?.replaceAll('_', ' ') || 'No evidence type'}</small></span> }, { key: 'risk_level', label: 'Overall risk', render: (v, row) => <RiskStatus level={v} score={row.risk_score} /> }, { key: 'quantum_status', label: 'Required action', render: v => <QuantumStatus status={v} /> }, { key: 'last_seen', label: 'Last observed', render: v => new Date(v).toLocaleDateString() }]} /><Pager data={data} page={page} setPage={setPage} /></div>}
    <AssetDrawer asset={selected} close={close} compare={compare} />
  </Page>
}
