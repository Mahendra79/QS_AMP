import { useState } from 'react'
import { Cpu, FlaskConical, Gauge, Play, TriangleAlert } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import api, { apiError } from '../api/client'
import { Badge, Button, EmptyState, ErrorState, FullLoading, MetricCard, Page, PageHeader, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi, usePolling } from '../hooks/useApi'

const PALETTE = ['#31b9df', '#8d7df7', '#37d6a0', '#f0c94d']
const DEMO_COLOR = '#ff9850'

export default function BenchmarkPage() {
  const state = useApi('/benchmarks/')
  const [selected, setSelected] = useState(['ML-KEM-768', 'ML-DSA-65'])
  const [iterations, setIterations] = useState(20)
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState(null)
  const { canWrite } = useRole()
  const latest = state.data?.runs?.[0]
  const running = latest?.status === 'running'
  usePolling(state.reload, running, 2000)
  const run = async () => {
    setBusy(true)
    try {
      await api.post('/benchmarks/run/', { algorithms: selected, iterations: Math.max(1, Math.min(200, Number(iterations) || 20)), force_demo: false })
      setToast({ message: 'Benchmark started. Results appear here when it finishes.' })
      state.reload({ silent: true })
    } catch (e) { setToast({ type: 'error', message: apiError(e) }) } finally { setBusy(false) }
  }
  if (state.loading && !state.data) return <Page><FullLoading label="Inspecting benchmark capabilities..." /></Page>
  if (state.error && !state.data) return <Page><ErrorState message={state.error} /></Page>
  const caps = state.data.capabilities
  const results = latest?.status === 'completed' ? latest.results || [] : []
  // Colour by implementation: pure-Python PQC and native OpenSSL timings differ by orders
  // of magnitude for reasons unrelated to the algorithms, so they must be distinguishable.
  const libraries = [...new Set(results.map(r => r.library))]
  const colorFor = r => r.data_source === 'demo' ? DEMO_COLOR : PALETTE[libraries.indexOf(r.library) % PALETTE.length]
  const chart = results.map(r => ({ name: `${r.algorithm} ${r.operation}`, median: Math.max(r.median, 0.0001), source: r.data_source, library: r.library, color: colorFor(r) }))
  const sources = new Set(results.map(r => r.data_source))
  const caveats = [...new Set(results.map(r => r.notes).filter(Boolean))]
  const sourceLabel = sources.size > 1 ? 'Mixed measured and demo data' : sources.has('demo') ? 'Demo benchmark' : 'Measured on this environment'
  return <Page><PageHeader eyebrow="Environment evidence" title="Cryptographic benchmarks" description="Measure supported implementations locally. Synthetic fallback data is always labeled and kept separate." />
    <div className="metric-grid compact"><MetricCard label="Platform" value={caps.environment.os} icon={Cpu} /><MetricCard label="Adapters" value={caps.adapters.length} icon={FlaskConical} /><MetricCard label="Algorithms" value={caps.algorithms.filter(a => a.adapter).length} detail={`of ${caps.algorithms.length} have an implementation`} icon={Gauge} tone="green" /></div>
    {canWrite && <Panel title="Run a benchmark" subtitle="Select implementation-backed algorithms and operation count"><div className="benchmark-form"><div className="algorithm-checks">{caps.algorithms.map(a => <label key={a.algorithm} className={a.adapter ? '' : 'unavailable'}><input type="checkbox" disabled={!a.adapter} checked={selected.includes(a.algorithm)} onChange={e => setSelected(e.target.checked ? [...selected, a.algorithm] : selected.filter(v => v !== a.algorithm))} /><span><strong>{a.algorithm}</strong><small>{a.adapter || 'Unavailable'} - {a.data_source || 'no implementation'}</small></span></label>)}</div><div className="benchmark-controls"><label>Iterations<input type="number" min="1" max="200" value={iterations} onChange={e => setIterations(e.target.value)} /></label><Button icon={Play} onClick={run} disabled={busy || running || !selected.length}>{running ? 'Running...' : busy ? 'Starting...' : 'Run benchmark'}</Button></div></div></Panel>}
    {!latest ? <EmptyState title="No benchmark runs" text="Run a benchmark to capture local evidence." />
      : running ? <Panel title={latest.name} subtitle="Measuring..."><div className="center-state compact"><span className="spin-dot" aria-hidden="true" />Benchmark running on the server. This page updates when it finishes.</div></Panel>
      : latest.status === 'failed' ? <Panel title={latest.name} subtitle="Failed"><ErrorState message={latest.error || 'The benchmark failed.'} /></Panel>
      : <Panel title={latest.name} subtitle={`${latest.adapter} - ${latest.platform}`} action={<Badge tone={sources.has('demo') ? 'medium' : 'safe'}>{sourceLabel}</Badge>}>
        {sources.has('demo') && <div className="info-note"><TriangleAlert />Orange bars are synthetic demo values and must not be used for engineering decisions.</div>}
        <div className="chart-legend">{libraries.map(lib => <span key={lib}><i style={{ background: results.find(r => r.library === lib)?.data_source === 'demo' ? DEMO_COLOR : PALETTE[libraries.indexOf(lib) % PALETTE.length] }} />{lib}</span>)}</div>
        <div className="comparison-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={chart}><CartesianGrid vertical={false} /><XAxis dataKey="name" tick={{ fontSize: 10 }} interval={0} angle={-10} /><YAxis scale="log" domain={[min => min / 2, max => max * 2]} tickFormatter={v => Number(v).toPrecision(2)} label={{ value: 'Median ms (log scale)', angle: -90, position: 'insideLeft', fontSize: 11 }} /><Tooltip formatter={(value, name, item) => [`${Number(value).toFixed(4)} ms (${item.payload.source}, ${item.payload.library})`, 'Median']} /><Bar dataKey="median" name="Median (ms)">{chart.map((row, i) => <Cell key={i} fill={row.color} />)}</Bar></BarChart></ResponsiveContainer></div>
        {caveats.length > 0 && <div className="caveats"><h3>Implementation caveats</h3><ul>{caveats.map(c => <li key={c}>{c}</li>)}</ul></div>}
      </Panel>}
    <Toast toast={toast} clear={() => setToast(null)} /></Page>
}
