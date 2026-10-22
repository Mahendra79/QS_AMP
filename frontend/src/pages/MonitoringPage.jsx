import { useState } from 'react'
import { Activity, CalendarClock, Play, Radio, Settings2 } from 'lucide-react'
import api, { apiError } from '../api/client'
import { Badge, Button, EmptyState, ErrorState, FullLoading, MetricCard, Page, PageHeader, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

const FREQUENCIES = [1, 6, 12, 24, 72, 168]

export default function MonitoringPage() {
  const state = useApi('/monitoring/')
  const [toast, setToast] = useState(null)
  const [busy, setBusy] = useState(false)
  const { canWrite } = useRole()
  const act = async (fn) => { setBusy(true); try { await fn() } catch (e) { setToast({ type: 'error', message: apiError(e) }) } finally { setBusy(false) } }
  // Evidence scans run in the background (202): report that they started, not that they finished.
  const scan = () => act(async () => {
    const { data } = await api.post('/monitoring/scan/', {})
    if (data.mode === 'simulated') setToast({ message: `Simulated monitoring pass recorded ${data.events.length} event(s).` })
    else setToast({ message: `Started ${data.jobs.length} scan(s)${data.skipped?.length ? `; ${data.skipped.length} already running` : ''}. Results appear in Discovery when they finish.` })
    state.reload({ silent: true })
  })
  const update = (patch, message) => act(async () => { await api.patch('/monitoring/', patch); setToast({ message }); state.reload({ silent: true }) })
  if (state.loading && !state.data) return <Page><FullLoading label="Loading monitoring telemetry..." /></Page>
  if (state.error && !state.data) return <Page><ErrorState message={state.error} /></Page>
  const cfg = state.data.configuration
  const when = v => v ? new Date(v).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Never'
  return <Page><PageHeader eyebrow="Continuous assurance" title="Cryptographic monitoring" description="Track changes to algorithms, dependencies, certificates, and risk posture over time." actions={canWrite && <><Button variant="secondary" icon={Settings2} disabled={busy} onClick={() => update({ enabled: !cfg.enabled }, cfg.enabled ? 'Monitoring paused.' : 'Monitoring enabled.')}>{cfg.enabled ? 'Pause monitoring' : 'Enable monitoring'}</Button><Button icon={Play} disabled={busy} onClick={scan}>{busy ? 'Working...' : 'Scan now'}</Button></>} />
    <div className="metric-grid compact"><MetricCard label="Status" value={cfg.enabled ? (state.data.scheduler_available ? 'Scheduled' : 'Configured') : 'Paused'} detail={cfg.enabled ? (state.data.scheduler_available ? `Next scan ${when(cfg.next_scan_at)}` : 'Run the monitoring command from cron') : ''} icon={Radio} tone={cfg.enabled && state.data.scheduler_available ? 'green' : 'orange'} />
      <MetricCard label="Frequency" value={canWrite ? <select className="inline-select" aria-label="Scan frequency" value={cfg.frequency_hours} disabled={busy} onChange={e => update({ frequency_hours: Number(e.target.value) }, 'Scan frequency updated.')}>{[...new Set([...FREQUENCIES, cfg.frequency_hours])].sort((a, b) => a - b).map(h => <option key={h} value={h}>{h < 24 ? `${h}h` : `${h / 24}d`}</option>)}</select> : `${cfg.frequency_hours}h`} icon={CalendarClock} />
      <MetricCard label="Last scan" value={when(cfg.last_scan_at)} icon={Activity} /><MetricCard label="Changes today" value={state.data.changes_today} icon={Activity} tone="purple" /></div>
    <Panel title="Change timeline" subtitle={cfg.simulated ? 'Demo monitoring events are clearly marked as simulated.' : 'Events from scheduled discovery scans.'}><div className="timeline">{state.data.events.map(event => <article key={event.id}><time>{new Date(event.occurred_at).toLocaleString()}</time><i className={`severity-${event.severity}`} /><div><h3>{event.title} {event.is_simulated && <Badge tone="neutral">simulated</Badge>}</h3><p>{event.detail}</p><span>{event.source_name || 'Organization-wide'} - {event.event_type.replaceAll('_', ' ')}</span></div></article>)}{!state.data.events.length && <EmptyState title="No monitoring events" text="Enable monitoring or run a scan to establish a change timeline." />}</div></Panel><Toast toast={toast} clear={() => setToast(null)} /></Page>
}
