import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RefreshCw, SlidersHorizontal, X } from 'lucide-react'
import api, { apiError, listData } from '../api/client'
import { Badge, Button, DataTable, ErrorState, FullLoading, IconButton, MetricCard, Page, PageHeader, Pager, Panel, RiskRing, RiskStatus } from '../components/UI'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'
import Toast from '../components/Toast'

const TRIAGE = [['open', 'Open'], ['accepted', 'Risk accepted'], ['false_positive', 'False positive'], ['resolved', 'Resolved']]

export default function RiskPage() {
  const summary = useApi('/risk/')
  const [triageFilter, setTriageFilter] = useState('open')
  const [page, setPage] = useState(1)
  useEffect(() => { setPage(1) }, [triageFilter])
  const findings = useApi(`/risk/findings/?page=${page}${triageFilter ? `&status=${triageFilter}` : ''}`)
  const [selected, setSelected] = useState(null)
  const [configuring, setConfiguring] = useState(false)
  const [weights, setWeights] = useState({})
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState(null)
  const { canWrite } = useRole()
  const [params, setParams] = useSearchParams()
  // Deep link (?finding=<id>, e.g. from a PDF report) opens that finding's details.
  useEffect(() => {
    const id = params.get('finding'); if (!id) return
    api.get(`/risk/findings/${id}/`).then(r => setSelected(r.data)).catch(e => setToast({ type: 'error', message: apiError(e) }))
  }, [params])
  const closeFinding = () => { setSelected(null); if (params.get('finding')) setParams({}) }
  const reload = () => { summary.reload({ silent: true }); findings.reload({ silent: true }) }
  const reassess = async () => {
    setBusy(true)
    try { await api.post('/risk/'); reload(); setToast({ message: 'Assessment complete.' }) }
    catch (e) { setToast({ type: 'error', message: apiError(e) }) } finally { setBusy(false) }
  }
  const configure = () => { setWeights(Object.fromEntries(summary.data.factors.map(f => [f.id, f.weight]))); setConfiguring(true) }
  const weightError = Object.values(weights).some(v => v === '' || !(Number(v) >= 0 && Number(v) <= 100)) ? 'Weights must be numbers from 0 to 100.' : ''
  const saveWeights = async () => {
    if (weightError) { setToast({ type: 'error', message: weightError }); return }
    const changed = summary.data.factors.filter(f => Number(weights[f.id]) !== f.weight)
    setBusy(true)
    try {
      // Sequential: every weight change re-scores the organization on the server.
      for (const f of changed) await api.patch(`/risk/factors/${f.id}/`, { weight: Number(weights[f.id]) })
      setConfiguring(false); reload()
      setToast({ message: changed.length ? 'Risk weights updated and assets re-scored.' : 'No weights changed.' })
    } catch (e) { setToast({ type: 'error', message: apiError(e) }) } finally { setBusy(false) }
  }
  const triage = async (finding, status) => {
    try {
      const { data } = await api.patch(`/risk/findings/${finding.id}/`, { status })
      setSelected(data); findings.reload({ silent: true }); setToast({ message: 'Finding updated.' })
    } catch (e) { setToast({ type: 'error', message: apiError(e) }) }
  }
  if (summary.loading && !summary.data) return <Page><FullLoading label="Evaluating quantum exposure..." /></Page>
  if (summary.error && !summary.data) return <Page><ErrorState message={summary.error} /></Page>
  const assessment = summary.data.assessment
  const label = TRIAGE.find(([key]) => key === triageFilter)?.[1]?.toLowerCase() || 'total'
  return <Page><PageHeader eyebrow="Explainable scoring" title="Quantum risk assessment" description="Every score is derived from visible, configurable factors and retained with its evidence." actions={canWrite && <Button icon={RefreshCw} onClick={reassess} disabled={busy}>{busy ? 'Assessing...' : 'Run assessment'}</Button>} />
    <div className="risk-overview"><RiskRing value={assessment.overall_score} /><div className="risk-metrics">{['critical', 'high', 'medium', 'low'].map((v, i) => <MetricCard key={v} label={v} value={assessment.counts?.[v] || 0} tone={['red', 'orange', 'yellow', 'blue'][i]} />)}</div></div>
    <Panel title="Risk factor profile" subtitle="Average factor score across the current inventory" action={canWrite && (configuring ? <><Button variant="ghost" onClick={() => setConfiguring(false)} disabled={busy}>Cancel</Button><Button onClick={saveWeights} disabled={busy || Boolean(weightError)}>{busy ? 'Saving...' : 'Save weights'}</Button></> : <Button variant="ghost" icon={SlidersHorizontal} onClick={configure}>Configure weights</Button>)}><div className="factor-grid">{summary.data.factors.map(f => <div key={f.key}><span><strong>{f.label}</strong><small>{configuring ? <input aria-label={`${f.label} weight`} type="number" min="0" max="100" value={weights[f.id] ?? f.weight} onChange={e => setWeights(v => ({ ...v, [f.id]: e.target.value }))} /> : `Weight ${f.weight}`}</small></span><div><i style={{ width: `${assessment.factor_averages?.[f.key] || 0}%` }} /></div><em>{assessment.factor_averages?.[f.key] || 0}</em></div>)}</div>{configuring && weightError && <div className="form-error" role="alert">{weightError}</div>}</Panel>
    <Panel title="Risk findings" subtitle={`${(findings.data?.count ?? listData(findings.data).length).toLocaleString()} ${label} findings`} action={<select aria-label="Finding status" value={triageFilter} onChange={e => setTriageFilter(e.target.value)}>{TRIAGE.map(([key, text]) => <option key={key} value={key}>{text}</option>)}<option value="">All findings</option></select>}>
      {findings.error && <ErrorState message={findings.error} />}
      <DataTable rows={listData(findings.data)} onRowClick={setSelected} columns={[{ key: 'title', label: 'Finding' }, { key: 'application', label: 'Application' }, { key: 'algorithm', label: 'Algorithm' }, { key: 'purpose', label: 'Purpose', render: v => v?.replaceAll('_', ' ') }, { key: 'severity', label: 'Overall risk', render: (v, row) => <RiskStatus level={v} score={row.score} /> }, { key: 'status', label: 'Triage', render: v => <Badge tone="neutral">{v.replaceAll('_', ' ')}</Badge> }]} />
      <Pager data={findings.data} page={page} setPage={setPage} /></Panel>
    {selected && <div className="drawer-layer" onMouseDown={closeFinding}><aside className="drawer" role="dialog" aria-label={selected.title} onMouseDown={e => e.stopPropagation()}><header><div><span className="eyebrow">Detailed risk analysis</span><h2>{selected.title}</h2></div><IconButton icon={X} label="Close details" onClick={closeFinding} /></header><div className="drawer-risk"><RiskStatus level={selected.severity} score={selected.score} /></div>
      {canWrite && <section><h3>Triage</h3><select aria-label="Triage status" value={selected.status} onChange={e => triage(selected, e.target.value)}>{TRIAGE.map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select><p className="muted-note">Kept across reassessments while the severity stays the same.</p></section>}
      <section><h3>Why this scored high</h3><p>{selected.reason}</p></section><section><h3>Recommended action</h3><p>{selected.recommended_action}</p></section><section><h3>Score components</h3><div className="component-list">{selected.components?.map(c => <div key={c.factor}><span><strong>{c.label}</strong><small>{c.explanation}</small></span><em>{c.score} x {c.weight}</em></div>)}</div></section></aside></div>}<Toast toast={toast} clear={() => setToast(null)} />
  </Page>
}
