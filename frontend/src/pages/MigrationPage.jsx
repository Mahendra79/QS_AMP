import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CalendarDays, CircleCheckBig, Plus, Route } from 'lucide-react'
import api, { apiError } from '../api/client'
import { Badge, Button, EmptyState, ErrorState, FullLoading, MetricCard, Page, PageHeader, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

const statuses = ['backlog', 'planned', 'in_progress', 'testing', 'verified', 'completed']
const done = ['verified', 'completed']
const phases = ['Inventory', 'Assessment', 'Planning', 'Hybrid', 'PQC', 'Verification', 'Decommission']

export default function MigrationPage() {
  const state = useApi('/migration/')
  const [toast, setToast] = useState(null)
  const { canWrite } = useRole()
  const [params] = useSearchParams()
  const focusTask = params.get('task')
  // Deep link (?task=<id>, e.g. from a PDF report): bring that card into view and highlight it.
  useEffect(() => {
    if (!focusTask || !state.data) return
    document.getElementById(`task-${focusTask}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [focusTask, state.data])
  const move = async (task, status) => {
    try {
      await api.patch(`/migration/tasks/${task.id}/`, { status })
      if (done.includes(status) && !done.includes(task.status)) {
        setToast({ message: 'Task completed. The inventory now records the target as declared; the next discovery scan verifies it.' })
      }
      state.reload({ silent: true })
    } catch (e) { setToast({ type: 'error', message: apiError(e) }) }
  }
  const setPhase = async (task, phase) => { try { await api.patch(`/migration/tasks/${task.id}/`, { phase }); state.reload({ silent: true }) } catch (e) { setToast({ type: 'error', message: apiError(e) }) } }
  const createPlan = async () => { try { const { data } = await api.post('/migration/', {}); setToast({ message: data.message }); state.reload({ silent: true }) } catch (e) { setToast({ type: 'error', message: apiError(e) }) } }
  if (state.loading && !state.data) return <Page><FullLoading label="Loading migration roadmap..." /></Page>
  if (state.error && !state.data) return <Page><ErrorState message={state.error} /></Page>
  return <Page>
    <PageHeader eyebrow="Crypto-agility roadmap" title="Migration planner" description="Move prioritized assets through evidence-backed hybrid and post-quantum transition phases." actions={canWrite && <Button icon={Plus} onClick={createPlan}>Generate plan</Button>} />
    <div className="metric-grid compact"><MetricCard label="Overall progress" value={`${state.data.progress}%`} icon={Route} tone="green" /><MetricCard label="Migration tasks" value={state.data.total} icon={CircleCheckBig} /><MetricCard label="Estimated effort" value={`${state.data.estimated_effort_days}d`} icon={CalendarDays} tone="purple" /></div>
    <Panel title="Transition phases" subtitle="Completion is derived from current inventory and verified migration work"><div className="phase-track">{phases.map(v => { const value = state.data.phase_progress?.[v.toLowerCase()] || 0; return <div className={value === 100 ? 'complete' : value > 0 ? 'active' : ''} key={v}><i>{value}%</i><span>{v}</span></div> })}</div></Panel>
    <div className="kanban">{statuses.map(status => <section key={status} aria-label={status.replaceAll('_', ' ')}><header><h2>{status.replaceAll('_', ' ')}</h2><span>{state.data.tasks.filter(t => t.status === status).length}</span></header><div>{state.data.tasks.filter(t => t.status === status).map(task => <article key={task.id} id={`task-${task.id}`} className={task.id === focusTask ? 'focused' : undefined}><div><Badge>{task.risk_level}</Badge><small>{task.phase}</small></div><h3>{task.title}</h3><p><strong>{task.current_algorithm}</strong><span>to</span>{task.target_algorithm || 'target not set'}</p>{task.notes && <p className="task-note">{task.notes}</p>}<footer><span>{task.owner_name || task.owner_username || 'Unassigned'}</span>{canWrite ? <span className="task-selects"><select aria-label={`Phase of ${task.title}`} value={task.phase} onChange={e => setPhase(task, e.target.value)}>{phases.map(p => <option key={p} value={p.toLowerCase()}>{p}</option>)}</select><select aria-label={`Status of ${task.title}`} value={task.status} onChange={e => move(task, e.target.value)}>{statuses.map(s => <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>)}</select></span> : <Badge tone="neutral">{task.status.replaceAll('_', ' ')}</Badge>}</footer></article>)}{!state.data.tasks.some(t => t.status === status) && <span className="kanban-empty">No tasks</span>}</div></section>)}</div>
    {!state.data.tasks.length && <EmptyState title="No migration plan created yet" />}<Toast toast={toast} clear={() => setToast(null)} />
  </Page>
}
