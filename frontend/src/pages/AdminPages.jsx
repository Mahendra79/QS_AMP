import { useEffect, useState } from 'react'
import { KeyRound, Plus, Save, ShieldCheck, Trash2 } from 'lucide-react'
import api, { apiError } from '../api/client'
import { Button, DataTable, EmptyState, FullLoading, IconButton, Page, PageHeader, Panel } from '../components/UI'
import Toast from '../components/Toast'
import { useAuth, useRole } from '../context/AuthContext'
import { useApi } from '../hooks/useApi'

function PasswordPanel({ notify }) {
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [busy, setBusy] = useState(false)
  const submit = async (e) => {
    e.preventDefault()
    if (form.new_password !== form.confirm) { notify({ type: 'error', message: 'The new passwords do not match.' }); return }
    setBusy(true)
    try {
      await api.post('/auth/change-password/', { current_password: form.current_password, new_password: form.new_password })
      setForm({ current_password: '', new_password: '', confirm: '' })
      notify({ message: 'Password changed.' })
    } catch (err) { notify({ type: 'error', message: apiError(err) }) } finally { setBusy(false) }
  }
  return <Panel title="Password" subtitle="Change the password for your account">
    <form className="form-grid three" onSubmit={submit}>
      <label>Current password<input type="password" autoComplete="current-password" value={form.current_password} onChange={e => setForm({ ...form, current_password: e.target.value })} required /></label>
      <label>New password<input type="password" autoComplete="new-password" minLength={8} value={form.new_password} onChange={e => setForm({ ...form, new_password: e.target.value })} required /></label>
      <label>Confirm new password<input type="password" autoComplete="new-password" minLength={8} value={form.confirm} onChange={e => setForm({ ...form, confirm: e.target.value })} required /></label>
      <div><Button type="submit" disabled={busy}>{busy ? 'Saving...' : 'Change password'}</Button></div>
    </form>
  </Panel>
}

function MfaPanel({ notify }) {
  const { profile, refresh } = useAuth()
  const enabled = profile?.user?.mfa_enabled
  const [setup, setSetup] = useState(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (fn) => { setBusy(true); try { await fn() } catch (err) { notify({ type: 'error', message: apiError(err) }) } finally { setBusy(false) } }
  const start = () => run(async () => { const { data } = await api.post('/auth/mfa/setup/'); setSetup(data); setCode('') })
  const verify = (e) => { e.preventDefault(); run(async () => { await api.post('/auth/mfa/verify/', { code: code.trim() }); setSetup(null); await refresh(); notify({ message: 'Multi-factor authentication is on.' }) }) }
  const disable = (e) => { e.preventDefault(); run(async () => { await api.post('/auth/mfa/disable/', { password }); setPassword(''); await refresh(); notify({ message: 'Multi-factor authentication is off.' }) }) }
  return <Panel title="Multi-factor authentication" subtitle={enabled ? 'Enabled - a one-time code is required at sign-in.' : 'Add an authenticator app (TOTP) to your account.'}>
    {enabled
      ? <form className="form-grid three" onSubmit={disable}><label>Password to confirm<input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required /></label><div><Button variant="secondary" type="submit" disabled={busy}>Turn off MFA</Button></div></form>
      : setup
        ? <form className="mfa-setup" onSubmit={verify}>
          <p>Add this key to your authenticator app, then enter the 6-digit code it shows.</p>
          <label>Setup key<input readOnly value={setup.secret} onFocus={e => e.target.select()} /></label>
          <label>Setup link (for apps that accept otpauth:// links)<input readOnly value={setup.otpauth_uri} onFocus={e => e.target.select()} /></label>
          <label>One-time code<input inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={code} onChange={e => setCode(e.target.value)} required autoFocus /></label>
          <div className="button-row"><Button type="submit" icon={ShieldCheck} disabled={busy}>Verify and enable</Button><Button type="button" variant="ghost" onClick={() => setSetup(null)}>Cancel</Button></div>
        </form>
        : <Button icon={ShieldCheck} onClick={start} disabled={busy}>Set up MFA</Button>}
  </Panel>
}

function ApiKeysPanel({ notify }) {
  const { canWrite } = useRole()
  const keys = useApi('/auth/api-keys/')
  const [name, setName] = useState('')
  const [created, setCreated] = useState(null)
  const create = async (e) => {
    e.preventDefault()
    try { const { data } = await api.post('/auth/api-keys/', { name }); setCreated(data); setName(''); keys.reload() }
    catch (err) { notify({ type: 'error', message: apiError(err) }) }
  }
  const revoke = async (key) => {
    if (!window.confirm(`Revoke the API key "${key.name}"? Integrations using it will stop working.`)) return
    try { await api.delete(`/auth/api-keys/${key.id}/`); keys.reload(); notify({ message: 'API key revoked.' }) }
    catch (err) { notify({ type: 'error', message: apiError(err) }) }
  }
  return <Panel title="API keys" subtitle="Keys authenticate automation (X-API-Key header) as you, in this workspace">
    {canWrite && <form className="form-grid three" onSubmit={create}><label>Key name<input value={name} maxLength={100} onChange={e => setName(e.target.value)} placeholder="e.g. CI pipeline" required /></label><div><Button type="submit" icon={Plus}>Create key</Button></div></form>}
    {created && <div className="info-note" role="status"><KeyRound /><span>Copy this key now - it cannot be shown again: <input readOnly value={created.key} onFocus={e => e.target.select()} aria-label="New API key" /></span></div>}
    <DataTable rows={Array.isArray(keys.data) ? keys.data : []} empty={keys.loading ? null : <EmptyState title="No API keys" />} columns={[
      { key: 'name', label: 'Name' }, { key: 'prefix', label: 'Prefix', render: v => <code>{v}...</code> },
      { key: 'created_at', label: 'Created', render: v => new Date(v).toLocaleDateString() },
      { key: 'last_used_at', label: 'Last used', render: v => v ? new Date(v).toLocaleString() : 'Never' },
      { key: 'id', label: '', render: (_, row) => canWrite && <IconButton icon={Trash2} className="danger" label={`Revoke ${row.name}`} onClick={() => revoke(row)} /> },
    ]} />
  </Panel>
}

export default function SettingsPage() {
  const state = useApi('/settings/')
  const { canWrite, role } = useRole()
  const [form, setForm] = useState(null)
  const [toast, setToast] = useState(null)
  const [section, setSection] = useState('Account')
  useEffect(() => { if (state.data) setForm(state.data.settings) }, [state.data])
  const thresholds = form?.risk?.thresholds
  const thresholdError = thresholds && !(thresholds.medium < thresholds.high && thresholds.high < thresholds.critical)
    ? 'Thresholds must increase: medium < high < critical.' : ''
  const save = async () => {
    if (thresholdError) { setToast({ type: 'error', message: thresholdError }); return }
    // Only the sections this page edits are sent.
    try {
      await api.patch('/settings/', { settings: { risk: { thresholds: form.risk.thresholds }, security: { require_mfa: form.security.require_mfa } } })
      setToast({ message: 'Settings saved.' }); state.reload()
    } catch (e) { setToast({ type: 'error', message: apiError(e) }) }
  }
  if (state.loading || !form) return <Page><FullLoading /></Page>
  const workspaceSection = section !== 'Account'
  return <Page>
    <PageHeader eyebrow="Workspace control" title="Settings" description="Manage your account, risk policy, and security controls."
      actions={workspaceSection && canWrite && <Button icon={Save} onClick={save} disabled={Boolean(thresholdError)}>Save changes</Button>} />
    <div className="settings-layout"><nav>{['Account', 'Risk model', 'Security'].map(v => <button className={section === v ? 'active' : ''} key={v} onClick={() => setSection(v)}>{v}</button>)}</nav><div>
      {section === 'Account' && <><PasswordPanel notify={setToast} /><MfaPanel notify={setToast} /><ApiKeysPanel notify={setToast} /></>}
      {section === 'Risk model' && <Panel title="Risk thresholds" subtitle="Scores at or above these values enter the corresponding severity. Changing them re-scores every asset.">
        <fieldset className="form-grid three" disabled={!canWrite}>{['medium', 'high', 'critical'].map(k => <label key={k}>{k}<input type="number" min="0" max="100" value={thresholds[k]} onChange={e => setForm(v => ({ ...v, risk: { ...v.risk, thresholds: { ...v.risk.thresholds, [k]: Number(e.target.value) } } }))} /></label>)}</fieldset>
        {thresholdError && <div className="form-error" role="alert">{thresholdError}</div>}</Panel>}
      {section === 'Security' && <Panel title="Security" subtitle="Authentication and session controls"><fieldset disabled={!canWrite}><label className="check-row"><input type="checkbox" checked={form.security.require_mfa} onChange={e => setForm(v => ({ ...v, security: { ...v.security, require_mfa: e.target.checked } }))} /><span><strong>Require multi-factor authentication</strong><small>Apply MFA enrollment policy to this workspace.</small></span></label></fieldset></Panel>}
      {!canWrite && workspaceSection && <p className="muted-note">Your role ({role}) can view but not change workspace settings.</p>}
    </div></div><Toast toast={toast} clear={() => setToast(null)} />
  </Page>
}
