import { AlertOctagon, Boxes, GitBranch, Radio, ShieldCheck, Sparkles } from 'lucide-react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { DataTable, ErrorState, FullLoading, MetricCard, Page, PageHeader, Panel, QuantumStatus, RiskRing, RiskStatus } from '../components/UI'
import { useApi } from '../hooks/useApi'

const colors = ['#ff4d6d', '#ff9850', '#f0c94d', '#58a6ff', '#37d6a0']

export default function DashboardPage() {
  const { data, loading, error } = useApi('/dashboard/')
  if (loading) return <Page><FullLoading label="Calculating security posture..." /></Page>
  if (error) return <Page><ErrorState message={error} /></Page>
  const m = data.metrics
  return <Page>
    <PageHeader eyebrow="Security posture" title="Quantum readiness overview" description="Current cryptographic exposure, readiness, and migration progress across your organization." actions={<span className="live-state"><i /> Monitoring {data.monitoring?.enabled ? 'configured' : 'paused'}</span>} />
    <div className="metric-grid"><MetricCard label="Total assets" value={m.total_assets.toLocaleString()} detail="Across connected sources" icon={Boxes} /><MetricCard label="Critical assets" value={m.critical_assets} detail="Immediate review" icon={AlertOctagon} tone="red" /><MetricCard label="High risk" value={m.high_risk} detail="Migration candidates" icon={ShieldCheck} tone="orange" /><MetricCard label="PQC deployment" value={`${m.pqc_readiness}%`} detail="PQC migration targets deployed" icon={Sparkles} tone="green" /><MetricCard label="Quantum exposure" value={`${m.quantum_exposure}/100`} detail="Weighted risk score" icon={Radio} tone="purple" /><MetricCard label="Migration" value={`${m.migration_progress}%`} detail="Verified or complete" icon={GitBranch} tone="cyan" /></div>
    <div className="dashboard-grid">
      <Panel title="Quantum risk" subtitle="Weighted exposure across inventoried assets" className="risk-panel"><RiskRing value={m.quantum_exposure} /></Panel>
      <Panel title="Algorithm distribution" subtitle="Most frequently observed primitives"><div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={data.algorithm_distribution} layout="vertical" margin={{ left: 8 }}><CartesianGrid horizontal={false} /><XAxis type="number" hide /><YAxis type="category" dataKey="algorithm" width={92} tick={{ fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip /><Bar dataKey="value" fill="#31b9df" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer></div></Panel>
      <Panel title="Risk distribution" subtitle={`${data.open_findings} open findings`}><div className="chart donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data.risk_distribution} dataKey="value" nameKey="name" innerRadius={58} outerRadius={83} paddingAngle={3}>{data.risk_distribution.map((_, i) => <Cell key={i} fill={colors[i]} />)}</Pie><Tooltip /></PieChart></ResponsiveContainer><div className="chart-legend">{data.risk_distribution.map((v, i) => <span key={v.name}><i style={{ background: colors[i] }} />{v.name}<strong>{v.value}</strong></span>)}</div></div></Panel>
      <Panel title="Readiness trajectory" subtitle="Calculated from inventory, assessments, and migration tasks"><div className="chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.readiness_trajectory}><defs><linearGradient id="readiness" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#37d6a0" stopOpacity=".35" /><stop offset="1" stopColor="#37d6a0" stopOpacity="0" /></linearGradient></defs><CartesianGrid vertical={false} /><XAxis dataKey="n" tick={{ fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis hide domain={[0, 100]} /><Tooltip /><Area type="monotone" dataKey="v" stroke="#37d6a0" fill="url(#readiness)" strokeWidth={2} /></AreaChart></ResponsiveContainer></div></Panel>
    </div>
    <Panel title="Recent cryptographic findings" subtitle="Latest assets observed across connected sources"><DataTable rows={data.recent_assets} columns={[{ key: 'name', label: 'Asset' }, { key: 'application', label: 'Application' }, { key: 'algorithm', label: 'Algorithm' }, { key: 'purpose', label: 'Purpose', render: v => v?.replaceAll('_', ' ') }, { key: 'risk_level', label: 'Overall risk', render: (v, row) => <RiskStatus level={v} score={row.risk_score} /> }, { key: 'quantum_status', label: 'Required action', render: v => <QuantumStatus status={v} /> }]} /></Panel>
  </Page>
}
