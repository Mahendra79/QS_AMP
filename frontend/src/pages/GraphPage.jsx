import { useEffect, useMemo, useState } from 'react'
import { Background, Controls, MarkerType, Position, ReactFlow } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { RefreshCw } from 'lucide-react'
import api, { apiError } from '../api/client'
import { useRole } from '../context/AuthContext'
import { Button, EmptyState, ErrorState, FullLoading, Page, PageHeader } from '../components/UI'
import { useApi } from '../hooks/useApi'

const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1, safe: 0 }
const TYPE_LABELS = { internet: 'Exposure', application: 'Application', certificate: 'Certificate', library: 'Library', algorithm: 'Cryptography' }

function positionGroup(items, x, centerY) {
  const gap = 120
  const start = Math.max(0, centerY - ((items.length - 1) * gap) / 2)
  return Object.fromEntries(items.map((item, index) => [item.id, { x, y: start + index * gap }]))
}

export default function GraphPage() {
  const state = useApi('/architecture/')
  const [selectedApp, setSelectedApp] = useState('')
  const applications = useMemo(() => (state.data?.nodes || [])
    .filter(node => node.type === 'application')
    .sort((a, b) => (RISK_ORDER[b.risk] - RISK_ORDER[a.risk]) || a.label.localeCompare(b.label)), [state.data])

  useEffect(() => {
    if (applications.length && !applications.some(app => app.id === selectedApp)) setSelectedApp(applications[0].id)
  }, [applications, selectedApp])

  const flow = useMemo(() => {
    if (!state.data || !selectedApp) return { nodes: [], edges: [], counts: {} }
    const directEdges = state.data.edges.filter(edge => edge.source === selectedApp || edge.target === selectedApp)
    const visibleIds = new Set([selectedApp])
    directEdges.forEach(edge => { visibleIds.add(edge.source); visibleIds.add(edge.target) })
    const visibleNodes = state.data.nodes.filter(node => visibleIds.has(node.id))
    const groups = {
      context: visibleNodes.filter(node => node.type === 'internet' || node.type === 'certificate'),
      app: visibleNodes.filter(node => node.type === 'application'),
      library: visibleNodes.filter(node => node.type === 'library'),
      algorithm: visibleNodes.filter(node => node.type === 'algorithm'),
    }
    const largest = Math.max(1, ...Object.values(groups).map(group => group.length))
    const centerY = ((largest - 1) * 120) / 2
    const positions = {
      ...positionGroup(groups.context, 20, centerY),
      ...positionGroup(groups.app, 280, centerY),
      ...positionGroup(groups.library, 540, centerY),
      ...positionGroup(groups.algorithm, groups.library.length ? 800 : 540, centerY),
    }
    return {
      nodes: visibleNodes.map(node => ({
        id: node.id,
        position: positions[node.id] || { x: 0, y: 0 },
        // Fixed left-to-right handles (rather than letting React Flow guess the
        // nearest side per edge) is what keeps every connector a clean,
        // non-crossing tree path instead of looping back on itself.
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { label: <div className="arch-label"><small>{TYPE_LABELS[node.type] || node.type}</small><strong title={node.label}>{node.label}</strong><span>{node.risk} risk</span></div> },
        className: `arch-node arch-${node.type} risk-${node.risk}`,
        draggable: false,
      })),
      edges: directEdges.map(edge => ({
        ...edge,
        type: 'smoothstep',
        pathOptions: { borderRadius: 14 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#6f95a5', width: 14, height: 14 },
        style: { stroke: '#88a9b7', strokeWidth: 1.5 },
      })),
      counts: { assets: groups.app[0]?.metadata?.assets || 0, libraries: groups.library.length, algorithms: groups.algorithm.length },
    }
  }, [state.data, selectedApp])

  const { canWrite } = useRole()
  const [rebuildError, setRebuildError] = useState('')
  const rebuild = async () => {
    setRebuildError('')
    try { await api.post('/architecture/'); state.reload() } catch (e) { setRebuildError(apiError(e)) }
  }
  return <Page className="graph-page">
    <PageHeader eyebrow="Application exposure" title="Crypto dependency map" description="Observed cryptography and supporting dependencies for each application." actions={canWrite && <Button variant="secondary" icon={RefreshCw} onClick={rebuild}>Refresh from inventory</Button>} />
    {rebuildError && <ErrorState message={rebuildError} />}
    {state.loading ? <FullLoading label="Mapping dependencies..." /> : state.error ? <ErrorState message={state.error} /> : !applications.length ? <EmptyState title="No application dependencies found" text="The map is built from observed inventory. Run discovery, or rebuild it if assets already exist." action={canWrite && <Button variant="secondary" icon={RefreshCw} onClick={rebuild}>Build from inventory</Button>} /> : <>
      <div className="architecture-toolbar">
        <label><span>Application</span><select value={selectedApp} onChange={event => setSelectedApp(event.target.value)}>{applications.map(app => <option key={app.id} value={app.id}>{app.label}</option>)}</select></label>
        <div><span><strong>{flow.counts.assets}</strong> observed assets</span><span><strong>{flow.counts.algorithms}</strong> crypto entries</span><span><strong>{flow.counts.libraries}</strong> libraries</span></div>
      </div>
      <div className="architecture-canvas"><ReactFlow nodes={flow.nodes} edges={flow.edges} fitView fitViewOptions={{ padding: .24 }} minZoom={.5} maxZoom={1.5} nodesConnectable={false} elementsSelectable={false}><Background color="#d7e2e8" gap={24} size={1} /><Controls showInteractive={false} /></ReactFlow><div className="graph-legend">{['critical', 'high', 'medium', 'safe'].map(value => <span key={value}><i className={`risk-${value}`} />{value}</span>)}</div></div>
    </>}
  </Page>
}
