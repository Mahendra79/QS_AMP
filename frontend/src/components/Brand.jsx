import { Orbit } from 'lucide-react'

export default function Brand({ compact = false }) {
  return <div className="brand">
    <span className="brand-symbol"><Orbit size={21} /></span>
    {!compact && <span><strong>QS-AMP</strong><small>Quantum Security</small></span>}
  </div>
}
