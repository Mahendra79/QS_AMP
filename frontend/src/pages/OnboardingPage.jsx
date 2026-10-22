import { useEffect, useState } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { Check, Code2, GitBranch, Globe2, Plus, Radio, Upload, X } from 'lucide-react'
import { useDropzone } from 'react-dropzone'
import Brand from '../components/Brand'
import { Button } from '../components/UI'
import api, { apiError } from '../api/client'
import { useAuth, useRole } from '../context/AuthContext'

const sourceTypes = [
  ['website', 'Website / Domain', 'Analyze TLS, certificates, protocols, and cryptographic exposure.', Globe2],
  ['zip', 'Source Code ZIP', 'Discover cryptographic APIs, algorithms, libraries, and dependencies.', Code2],
  ['public_repo', 'Public Repository', 'Clone a public Git repository and discover cryptographic usage in its source.', GitBranch],
]

function AddSourceModal({ initial, close, complete }) {
  const [type, setType] = useState(initial || 'website')
  const [form, setForm] = useState({ name: '', target: '', branch: 'main', monitoring_enabled: false })
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const dropzone = useDropzone({ accept: { 'application/zip': ['.zip'] }, maxFiles: 1, onDrop: files => setFile(files[0]) })
  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') close() }
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey)
  }, [close])
  const needsFile = type === 'zip'
  const needsRepo = type === 'public_repo'
  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setError('')
    try {
      const body = new FormData()
      // A ZIP source is identified by its file; URL fields only apply to website/repository sources.
      const target = needsFile ? file?.name : form.target.trim()
      body.append('source_type', type); body.append('name', form.name.trim() || target || 'New source')
      body.append('target', target || ''); body.append('branch', form.branch)
      body.append('monitoring_enabled', needsFile ? false : form.monitoring_enabled)
      if (needsFile && file) body.append('upload', file)
      const { data } = await api.post('/discovery/sources/', body)
      complete(data.scan_job)
    } catch (err) { setError(apiError(err)); setBusy(false) }
  }
  const switchType = (key) => { setType(key); setFile(null); setError(''); setForm(f => ({ ...f, target: '' })) }
  return <motion.div className="modal" role="dialog" aria-label="New discovery source" initial={{ opacity: 0, scale: .97 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: .97 }}>
    <header><div><span className="eyebrow">New discovery source</span><h2>What would you like to analyze?</h2></div><button className="icon-button" onClick={close} aria-label="Close"><X /></button></header>
    <div className="source-tabs" role="tablist">{sourceTypes.map(([key, label, , Icon]) => <button type="button" role="tab" aria-selected={type === key} className={type === key ? 'active' : ''} key={key} onClick={() => switchType(key)}><Icon />{label.split(' ')[0]}</button>)}</div>
    <form onSubmit={submit}>
      <label>Source name<input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. payments-api" /></label>
      {needsFile && <div {...dropzone.getRootProps({ className: `dropzone ${dropzone.isDragActive ? 'active' : ''}` })}><input {...dropzone.getInputProps()} /><Upload /><strong>{file ? file.name : 'Drop a ZIP archive here'}</strong><span>or click to browse</span></div>}
      {type === 'website' && <label>Website URL<input type="url" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} placeholder="https://payments.example.com" required /></label>}
      {needsRepo && <><label>Repository URL<input type="url" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} placeholder="https://github.com/org/repo" required /></label>
        <label>Branch<input value={form.branch} onChange={e => setForm({ ...form, branch: e.target.value })} placeholder="main" /></label></>}
      {!needsFile && <label className="check-row"><input type="checkbox" checked={form.monitoring_enabled} onChange={e => setForm({ ...form, monitoring_enabled: e.target.checked })} /><span><strong>Continuous monitoring</strong><small>Re-scan this source on the configured schedule.</small></span></label>}
      <div className="scan-options"><span>Analysis includes</span><div>{(type === 'website' ? ['TLS versions', 'Key exchange (incl. hybrid PQC)', 'Cipher suite', 'Certificate', 'CBOM'] : ['Code references', 'Dependencies', 'Certificates and keys', 'PQC compatibility', 'CBOM']).map(v => <small key={v}><Check />{v}</small>)}</div></div>
      {error && <div className="form-error" role="alert">{error}</div>}
      <footer><Button type="button" variant="ghost" onClick={close}>Cancel</Button><Button type="submit" disabled={busy || (needsFile && !file)} icon={Radio}>{busy ? 'Starting...' : 'Start discovery'}</Button></footer>
    </form>
  </motion.div>
}

function ScanExperience({ job, done, retry }) {
  const [state, setState] = useState(job)
  const [pollError, setPollError] = useState('')
  useEffect(() => {
    if (!state?.id || state.status === 'completed' || state.status === 'failed') return undefined
    let failures = 0
    const timer = setInterval(async () => {
      try {
        const { data } = await api.get(`/discovery/scans/${state.id}/`)
        failures = 0; setPollError(''); setState(data)
        if (data.status === 'completed' || data.status === 'failed') clearInterval(timer)
      } catch (err) {
        // Transient network errors keep polling; give up only after repeated failures.
        failures += 1
        if (failures >= 5) { clearInterval(timer); setPollError(`Lost contact with the scan: ${apiError(err)}`) }
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [state?.id, state?.status])
  if (!state?.id) return <div className="scan-experience"><div className="scan-core complete"><Check /></div><span className="eyebrow">Configuration complete</span><h2>Your integration is ready.</h2><Button onClick={done}>Enter QS-AMP</Button></div>
  const stages = state.stages || []
  return <div className="scan-experience"><div className={`scan-core ${state.status}`}><Radio /></div><span className="eyebrow">QS-AMP discovery engine</span><h2>{state.status === 'completed' ? 'Discovery complete' : state.status === 'failed' ? 'Discovery failed' : state.stage || 'Preparing analysis'}</h2><div className="scan-progress"><i style={{ width: `${state.progress || 3}%` }} /></div><div className="stage-list">{stages.map((s, i) => <span className={i < state.stage_index ? 'done' : i === state.stage_index ? 'current' : ''} key={s}>{i < state.stage_index ? <Check /> : <i />}{s}</span>)}</div>{state.status === 'completed' && <Button onClick={done}>Enter QS-AMP</Button>}{(state.status === 'failed' || pollError) && <><p className="form-error" role="alert">{pollError || state.error}</p><div className="button-row"><Button variant="secondary" onClick={retry}>Try another source</Button><Button variant="ghost" onClick={done}>Go to dashboard</Button></div></>}</div>
}

export default function OnboardingPage() {
  const { profile, refresh } = useAuth()
  const [params] = useSearchParams()
  const requested = params.get('add')
  const [modal, setModal] = useState(Boolean(requested))
  const [selected, setSelected] = useState(requested === '1' ? null : requested)
  const [scan, setScan] = useState(null)
  const navigate = useNavigate()
  const { canWrite } = useRole()
  if (profile?.active_organization?.source_count > 0 && !scan && !requested) return <Navigate to="/dashboard" replace />
  const done = async () => { await refresh(); navigate('/dashboard') }
  return <div className="onboarding"><header><Brand /><div><span>{profile?.active_organization?.name}</span><span className="badge badge-safe">Secure workspace</span></div></header><main><motion.div className="onboarding-title" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}><span className="eyebrow">Cryptographic visibility starts here</span><h1>Understand your cryptography.<br />Prepare for the quantum era.</h1><p>Discover cryptographic assets, assess quantum exposure, compare PQC alternatives, monitor changes, and plan your migration.</p>{canWrite ? <Button icon={Plus} onClick={() => setModal(true)}>Add your first asset</Button> : <><p className="info-note">Your role ({profile?.active_organization?.role}) is read-only. Ask an owner, admin, or analyst to connect the first source.</p><Button variant="secondary" onClick={() => navigate('/dashboard')}>Go to dashboard</Button></>}</motion.div>{canWrite && <div className="source-grid">{sourceTypes.map(([key, title, description, Icon], i) => <motion.button key={key} className="source-card" onClick={() => { setSelected(key); setModal(true) }} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .05 * i }}><span><Icon /></span><h2>{title}</h2><p>{description}</p><small>Configure source <Plus /></small></motion.button>)}</div>}</main>
    <AnimatePresence>{modal && <div className="modal-layer" onMouseDown={() => setModal(false)}><div onMouseDown={e => e.stopPropagation()}><AddSourceModal initial={selected} close={() => setModal(false)} complete={job => { setModal(false); setScan(job || {}) }} /></div></div>}</AnimatePresence>
    <AnimatePresence>{scan && <div className="scan-layer"><ScanExperience job={scan} done={done} retry={() => { setScan(null); setModal(true) }} /></div>}</AnimatePresence>
  </div>
}
