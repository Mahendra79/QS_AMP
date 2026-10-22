import { useMemo, useRef, useState } from 'react'
import { Background, Controls, ReactFlow } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Braces, FileCode2, FileJson, Network, Table2, Upload } from 'lucide-react'
import api, { apiError, downloadFile, listData } from '../api/client'
import { Badge, Button, DataTable, EmptyState, ErrorState, IconButton, Loading, Page, PageHeader, Pager, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

// Columns left to right: what uses cryptography -> where -> what cryptography.
const COLUMN = { application: 0, library: 1, file: 2, protocol: 3, algorithm: 3, certificate: 4, 'related-crypto-material': 4, key: 4 }

function layout(nodes) {
  const rows = {}
  return nodes.map(n => {
    const col = COLUMN[n.type] ?? COLUMN[n.component_type] ?? 3
    const row = rows[col] = (rows[col] ?? -1) + 1
    return { id: n.id, position: { x: col * 250, y: row * 90 }, data: { label: n.label }, className: `flow-node risk-${n.risk || 'safe'}` }
  })
}

export default function CBOMPage() {
  const [page, setPage] = useState(1)
  const docs = useApi(`/cbom/?page=${page}`)
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [graph, setGraph] = useState(null)
  const [view, setView] = useState('table')
  const [toast, setToast] = useState(null)
  const [busy, setBusy] = useState(false)
  const { canWrite } = useRole()
  const uploadRef = useRef(null)
  const fail = e => setToast({ type: 'error', message: apiError(e) })
  const choose = async (doc) => {
    setSelected(doc)
    try { const [{ data: d }, { data: g }] = await Promise.all([api.get(`/cbom/${doc.id}/`), api.get(`/cbom/${doc.id}/graph/`)]); setDetail(d); setGraph(g) }
    catch (e) { fail(e) }
  }
  const generate = async () => { setBusy(true); try { const { data } = await api.post('/cbom/generate/', {}); setToast({ message: 'CBOM generated.' }); docs.reload({ silent: true }); choose(data) } catch (e) { fail(e) } finally { setBusy(false) } }
  const upload = async (event) => { const file = event.target.files?.[0]; if (!file) return; setBusy(true); try { const body = new FormData(); body.append('file', file); body.append('name', file.name); const { data } = await api.post('/cbom/upload/', body); setToast({ message: `Imported ${data.assets_imported} new asset(s).` }); docs.reload({ silent: true }); choose(data) } catch (e) { fail(e) } finally { event.target.value = ''; setBusy(false) } }
  const download = (fmt) => downloadFile(`/cbom/${detail.id}/export/${fmt}/`, `${detail.name}.cdx.${fmt}`).catch(fail)
  const flow = useMemo(() => {
    if (!graph) return { nodes: [], edges: [] }
    return { nodes: layout(graph.nodes), edges: graph.edges.map(e => ({ ...e, style: { stroke: '#5f8ea0' } })) }
  }, [graph])
  const rows = listData(docs.data)
  return <Page><PageHeader eyebrow="CycloneDX 1.6" title="CBOM explorer" description="Inspect cryptographic components and the relationships between applications, libraries, algorithms, keys, protocols, and certificates." actions={canWrite && <><input ref={uploadRef} type="file" accept=".json,.xml,application/json,application/xml,text/xml" hidden onChange={upload} /><Button variant="secondary" icon={Upload} disabled={busy} onClick={() => uploadRef.current?.click()}>Upload</Button><Button icon={Braces} disabled={busy} onClick={generate}>Generate CBOM</Button></>} />
    {docs.error && <ErrorState message={docs.error} />}{docs.loading && !docs.data ? <Loading /> : <><div className="cbom-docs">{rows.map(doc => <button key={doc.id} className={selected?.id === doc.id ? 'active' : ''} aria-pressed={selected?.id === doc.id} onClick={() => choose(doc)}><Braces /><span><strong>{doc.name}</strong><small>{doc.component_count} components - {doc.spec_format} {doc.spec_version}</small></span><Badge>{doc.validation?.valid === false ? 'invalid' : 'valid'}</Badge></button>)}{!rows.length && <EmptyState title="No CBOM available" text="Generate one from inventory or upload a CycloneDX document." action={canWrite && <Button onClick={generate}>Generate CBOM</Button>} />}</div><Pager data={docs.data} page={page} setPage={setPage} /></>}
    {detail && <Panel title={detail.name} subtitle={`${detail.component_count} components with ${detail.dependencies?.length || 0} dependency relationships`} action={<div className="segmented"><button className={view === 'table' ? 'active' : ''} onClick={() => setView('table')} aria-label="Table view" title="Table view"><Table2 /></button><button className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')} aria-label="Graph view" title="Graph view"><Network /></button><button className={view === 'json' ? 'active' : ''} onClick={() => setView('json')} aria-label="JSON view" title="JSON view"><Braces /></button><IconButton icon={FileJson} label="Download CycloneDX JSON" onClick={() => download('json')} /><IconButton icon={FileCode2} label="Download CycloneDX XML" onClick={() => download('xml')} /></div>}>
      {view === 'table' && <DataTable rows={detail.components} columns={[{ key: 'name', label: 'Component' }, { key: 'component_type', label: 'Type' }, { key: 'asset_type', label: 'Crypto asset' }, { key: 'version', label: 'Version' }, { key: 'risk_level', label: 'Risk', render: v => <Badge>{v}</Badge> }]} />}
      {view === 'graph' && <div className="flow-canvas"><ReactFlow nodes={flow.nodes} edges={flow.edges} fitView nodesConnectable={false}><Background color="#d7e2e8" gap={24} /><Controls showInteractive={false} /></ReactFlow></div>}
      {view === 'json' && <pre className="json-view">{JSON.stringify(detail.raw, null, 2)}</pre>}
    </Panel>}<Toast toast={toast} clear={() => setToast(null)} /></Page>
}
