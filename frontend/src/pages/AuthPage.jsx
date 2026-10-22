import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowRight, Check, Eye, EyeOff, KeyRound, LockKeyhole, UserRound } from 'lucide-react'
import Brand from '../components/Brand'
import { Button } from '../components/UI'
import { useAuth } from '../context/AuthContext'
import { apiError, apiErrorCode } from '../api/client'

export default function AuthPage({ mode }) {
  const { profile, login, register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '', full_name: '', organization_name: '' })
  const [otp, setOtp] = useState('')
  const [needsOtp, setNeedsOtp] = useState(false)
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (profile) return <Navigate to={profile.active_organization?.source_count ? '/dashboard' : '/'} replace />
  const submit = async (e, demo = false) => {
    e?.preventDefault(); setBusy(true); setError('')
    try {
      if (demo) await login('demo', 'QuantumReady!2026')
      else if (mode === 'login') await login(form.username, form.password, needsOtp ? otp.trim() : '')
      else await register(form)
      navigate('/')
    } catch (err) {
      // Accounts with MFA enabled get a second step instead of a dead end.
      if (apiErrorCode(err) === 'mfa_required') { setNeedsOtp(true); setError('Enter the 6-digit code from your authenticator app.') }
      else setError(apiError(err))
    } finally { setBusy(false) }
  }
  return <div className="auth-shell">
    <section className="auth-visual">
      <Brand /><div className="auth-copy"><span className="eyebrow">Cryptographic intelligence</span><h1>Prepare your security architecture for the quantum era.</h1><p>Discover cryptographic dependencies, quantify exposure, and build an evidence-backed migration plan.</p>
        <ul><li><Check /> Purpose-aware PQC recommendations</li><li><Check /> CycloneDX cryptographic bill of materials</li><li><Check /> Transparent, explainable risk scoring</li></ul></div>
      <div className="quantum-field" aria-hidden="true"><i /><i /><i /><i /><span /></div>
    </section>
    <motion.section className="auth-form-wrap" initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}>
      <form className="auth-form" onSubmit={submit}><div><span className="eyebrow">{mode === 'login' ? 'Welcome back' : 'Create your workspace'}</span><h2>{mode === 'login' ? 'Sign in to QS-AMP' : 'Start your assessment'}</h2><p>{mode === 'login' ? 'Continue to your quantum security workspace.' : 'Set up a secure organization in a few moments.'}</p></div>
        {mode === 'register' && <><label>Full name<input value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} required /></label><label>Organization<input value={form.organization_name} onChange={e => setForm({ ...form, organization_name: e.target.value })} required /></label></>}
        <label>Username<div className="input-icon"><UserRound /><input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} autoComplete="username" required /></div></label>
        <label>Password<div className="input-icon"><LockKeyhole /><input type={show ? 'text' : 'password'} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required minLength={8} /><button type="button" onClick={() => setShow(v => !v)} aria-label={show ? 'Hide password' : 'Show password'}>{show ? <EyeOff /> : <Eye />}</button></div></label>
        {needsOtp && <label>One-time code<div className="input-icon"><KeyRound /><input value={otp} onChange={e => setOtp(e.target.value)} inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,8}" maxLength={8} required autoFocus /></div></label>}
        {error && <div className={needsOtp && !otp ? 'info-note' : 'form-error'} role="alert">{error}</div>}
        <Button type="submit" disabled={busy} icon={ArrowRight}>{busy ? 'Please wait...' : mode === 'login' ? 'Sign in' : 'Create workspace'}</Button>
        {mode === 'login' && <button type="button" className="demo-login" onClick={e => submit(e, true)} disabled={busy}>Explore the demo workspace</button>}
        <p className="auth-switch">{mode === 'login' ? 'New to QS-AMP?' : 'Already have an account?'} <Link to={mode === 'login' ? '/register' : '/login'}>{mode === 'login' ? 'Create an account' : 'Sign in'}</Link></p>
      </form>
    </motion.section>
  </div>
}
