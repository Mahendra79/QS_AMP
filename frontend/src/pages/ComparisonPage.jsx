import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { GitCompareArrows, Info, Scale } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import api, { apiError } from '../api/client'
import { Badge, Button, EmptyState, ErrorState, Page, PageHeader, Panel, QuantumStatus } from '../components/UI'
import { useRole } from '../context/AuthContext'

const COMPARABLE = ['kem', 'signature', 'protocol']
const FAMILY_LABEL = { kem: 'ML-KEM', signature: 'ML-DSA / SLH-DSA', protocol: 'ML-KEM key exchange', pqc: 'Already post-quantum' }

// Stored benchmark medians for one algorithm, labelled by data source. Never mixed:
// measured and demo values are shown separately.
function BenchmarkEvidence({ benchmarks, operations }) {
  const sources = ['measured', 'demo'].filter(s => Object.keys(benchmarks?.[s] || {}).length)
  if (!sources.length) return <p className="muted-note">No benchmark results for this algorithm yet. Run one on the Benchmarks page.</p>
  return <div className="bench-evidence">{sources.map(source => <div key={source}><Badge tone={source === 'demo' ? 'medium' : 'safe'}>{source === 'demo' ? 'Demo (synthetic)' : 'Measured'}</Badge>
    <dl>{operations.filter(op => benchmarks[source][op]).map(op => <div key={op}><dt>{op}</dt><dd>{benchmarks[source][op].median_ms.toFixed(3)} ms <small>{benchmarks[source][op].library}</small></dd></div>)}</dl></div>)}</div>
}

export default function ComparisonPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { canWrite } = useRole()
  const [asset, setAsset] = useState(null)
  const [recommendation, setRecommendation] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const id = params.get('asset'); if (!id) return
    setResult(null); setError('')
    Promise.all([api.get(`/inventory/${id}/`), api.get(`/comparison/recommend/${id}/`)]).then(([a, r]) => { setAsset(a.data); setRecommendation(r.data) }).catch(e => setError(apiError(e)))
  }, [params])
  const atype = recommendation?.analysis_type
  // A protocol is compared through its key-exchange group, so only KEM candidates are sent.
  const eligible = (recommendation?.candidates || []).filter(c => atype !== 'protocol' || c.applies_to === 'key_exchange')
  const chosen = (eligible.some(c => c.meets_requirement) ? eligible.filter(c => c.meets_requirement) : eligible).slice(0, 3).map(c => c.candidate)
  const compare = async () => { setBusy(true); setError(''); try { const { data } = await api.post('/comparison/run/', { asset_id: asset.id, pqc_algorithms: chosen }); setResult(data.result) } catch (e) { setError(apiError(e)) } finally { setBusy(false) } }
  const sizeData = result ? [{ name: result.classical.algorithm, publicKey: result.classical.sizes.public_key, output: result.classical.sizes.output }, ...result.candidates.map(c => ({ name: c.algorithm, publicKey: c.sizes.public_key, output: c.sizes.output }))] : []
  const canCompare = COMPARABLE.includes(atype) && chosen.length > 0
  return <Page><PageHeader eyebrow="Purpose-aware analysis" title="PQC comparison" description="Compare applicable post-quantum candidates by primitive, security category, size, compatibility, and measured evidence." />
    {error && <ErrorState message={error} />}{!asset ? <EmptyState title="Select an inventory asset" text="Open an RSA, ECDH, or signature asset from the inventory and choose Compare with PQC." action={<Button onClick={() => navigate('/inventory')}>Browse inventory</Button>} /> : <>
      <div className="comparison-hero"><article><small>Existing cryptography</small><h2>{asset.algorithm}</h2><span>{asset.application}</span><QuantumStatus status={asset.quantum_status} /></article><div><GitCompareArrows /><span>{recommendation?.purpose?.replaceAll('_', ' ')}</span></div><article><small>Applicable families</small><h2>{FAMILY_LABEL[atype] || 'Separate analysis'}</h2><span>{atype === 'pqc' ? 'No replacement needed' : 'NIST standardized candidates'}</span><Badge tone="safe">Purpose matched</Badge></article></div>
      <Panel title="Recommendation analysis" subtitle={recommendation?.notes} action={canWrite && canCompare && <Button icon={Scale} onClick={compare} disabled={busy}>{busy ? 'Comparing...' : 'Run comparison'}</Button>}><div className="candidate-cards">{recommendation?.candidates?.map(c => <article key={`${c.candidate}-${c.applies_to}`}><div><h3>{c.candidate}</h3><Badge tone={c.meets_requirement ? 'safe' : 'medium'}>{c.security_level}</Badge></div><p>{c.reason}</p><ul>{c.tradeoffs.map(t => <li key={t}>{t}</li>)}</ul></article>)}</div>{recommendation && !recommendation.candidates?.length && <p className="muted-note">No PQC replacement applies to this asset type; follow the analysis above.</p>}</Panel>
    </>}
    {result && <><Panel title="Specification size comparison" subtitle="Published key and output sizes (bytes). These are not benchmark timings.">{result.notes?.map(n => <div className="info-note" key={n}><Info />{n}</div>)}<div className="comparison-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={sizeData}><CartesianGrid vertical={false} /><XAxis dataKey="name" tick={{ fontSize: 11 }} /><YAxis /><Tooltip /><Legend /><Bar dataKey="publicKey" fill="#31b9df" name="Public key (bytes)" /><Bar dataKey="output" fill="#8d7df7" name="Ciphertext/signature (bytes)" /></BarChart></ResponsiveContainer></div></Panel>
      <Panel title={`${result.classical.algorithm} (current)`} subtitle="Stored benchmark evidence"><BenchmarkEvidence benchmarks={result.classical.benchmarks} operations={result.operations} /></Panel>
      <div className="comparison-results">{result.candidates.map(c => <Panel key={c.algorithm} title={c.algorithm} subtitle={`${c.standard} - ${c.security.category_label}`}><div className="spec-grid"><span>Public key<strong>{c.sizes.public_key} B</strong></span><span>Private key<strong>{c.sizes.private_key} B</strong></span><span>{c.sizes.output_kind}<strong>{c.sizes.output} B</strong></span><span>Migration effort<strong>{c.migration_impact.effort}</strong></span></div><div className="info-note"><Info />{c.security.note}</div><h3>Benchmark evidence</h3><BenchmarkEvidence benchmarks={c.benchmarks} operations={result.operations} /><h3>Compatibility considerations</h3><ul>{c.compatibility.map(v => <li key={v}>{v}</li>)}</ul></Panel>)}</div></>}
  </Page>
}
