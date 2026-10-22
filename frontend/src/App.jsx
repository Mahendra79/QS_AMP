import { lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import WorkspaceLayout from './layouts/WorkspaceLayout'
import AuthPage from './pages/AuthPage'
import OnboardingPage from './pages/OnboardingPage'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const DiscoveryPage = lazy(() => import('./pages/DiscoveryPage'))
const InventoryPage = lazy(() => import('./pages/InventoryPage'))
const CBOMPage = lazy(() => import('./pages/CBOMPage'))
const RiskPage = lazy(() => import('./pages/RiskPage'))
const ComparisonPage = lazy(() => import('./pages/ComparisonPage'))
const GraphPage = lazy(() => import('./pages/GraphPage'))
const MonitoringPage = lazy(() => import('./pages/MonitoringPage'))
const MigrationPage = lazy(() => import('./pages/MigrationPage'))
const BenchmarkPage = lazy(() => import('./pages/BenchmarkPage'))
const ReportsPage = lazy(() => import('./pages/ReportsPage'))
const AlertsPage = lazy(() => import('./pages/AlertsPage'))
const AdminPages = lazy(() => import('./pages/AdminPages'))

function Protected({ children }) {
  const { profile, loading } = useAuth()
  if (loading) return <div className="app-loader"><span className="brand-mark">Q</span><span>Securing workspace...</span></div>
  return profile ? children : <Navigate to="/login" replace />
}

// Routes are not keyed by pathname: the workspace layout (sidebar state, search
// palette) stays mounted across navigation. Page transitions are animated by
// each page's own <Page> component; Suspense lives inside the layout.
export default function App() {
  return <Routes>
    <Route path="/login" element={<AuthPage mode="login" />} />
    <Route path="/register" element={<AuthPage mode="register" />} />
    <Route path="/" element={<Protected><OnboardingPage /></Protected>} />
    <Route element={<Protected><WorkspaceLayout /></Protected>}>
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/discovery" element={<DiscoveryPage />} />
      <Route path="/inventory" element={<InventoryPage />} />
      <Route path="/cbom" element={<CBOMPage />} />
      <Route path="/risk" element={<RiskPage />} />
      <Route path="/comparison" element={<ComparisonPage />} />
      <Route path="/architecture" element={<GraphPage />} />
      <Route path="/monitoring" element={<MonitoringPage />} />
      <Route path="/migration" element={<MigrationPage />} />
      <Route path="/benchmarks" element={<BenchmarkPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/alerts" element={<AlertsPage />} />
      <Route path="/settings" element={<AdminPages />} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
}
