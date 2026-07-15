import { useState } from 'react';
import { motion } from 'framer-motion';
import { BookOpen, Shield, AlertTriangle, Save, RotateCcw } from 'lucide-react';

interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  actions: string[];
}

const defaultPolicies: Policy[] = [
  { id: 'p-1', name: 'Auto-Isolate on Critical', description: 'Automatically isolate host when critical threat is detected', enabled: false, severity: 'critical', actions: ['isolate_network', 'capture_snapshot'] },
  { id: 'p-2', name: 'Kill Suspicious Processes', description: 'Kill processes that match known malicious patterns', enabled: true, severity: 'high', actions: ['kill_process', 'log_forensics'] },
  { id: 'p-3', name: 'Block Malicious IPs', description: 'Automatically block IPs associated with C2 servers', enabled: true, severity: 'high', actions: ['block_ip'] },
  { id: 'p-4', name: 'Alert on Kernel Changes', description: 'Trigger alert when kernel modules are loaded or modified', enabled: true, severity: 'medium', actions: ['alert', 'log_forensics'] },
  { id: 'p-5', name: 'Monitor Privilege Escalation', description: 'Detect and alert on privilege escalation attempts', enabled: true, severity: 'critical', actions: ['alert', 'kill_process'] },
  { id: 'p-6', name: 'File Integrity Monitoring', description: 'Monitor critical system files for unauthorized changes', enabled: true, severity: 'medium', actions: ['alert', 'capture_snapshot'] },
];

export default function Policies() {
  const [policies, setPolicies] = useState(defaultPolicies);
  const [saved, setSaved] = useState(false);

  const toggle = (id: string) => {
    setPolicies((prev) => prev.map((p) => p.id === id ? { ...p, enabled: !p.enabled } : p));
    setSaved(false);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium px-2 py-1 rounded-lg"
            style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.4)' }}>
            {policies.filter((p) => p.enabled).length}/{policies.length} active
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPolicies(defaultPolicies)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.5)' }}>
            <RotateCcw size={11} /> Reset
          </button>
          <button onClick={handleSave}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all"
            style={{ background: saved ? 'rgba(34,197,94,0.1)' : 'rgba(59,130,246,0.1)', border: `1px solid ${saved ? 'rgba(34,197,94,0.15)' : 'rgba(59,130,246,0.15)'}`, color: saved ? '#4ADE80' : '#60A5FA' }}>
            <Save size={11} /> {saved ? 'Saved' : 'Save Changes'}
          </button>
        </div>
      </div>

      <div className="space-y-2">
        {policies.map((policy, i) => (
          <motion.div key={policy.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="sx-card p-4"
            style={{ opacity: policy.enabled ? 1 : 0.5 }}>
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0 mt-0.5"
                style={{ background: policy.severity === 'critical' ? 'rgba(239,68,68,0.08)' : policy.severity === 'high' ? 'rgba(249,115,22,0.08)' : 'rgba(234,179,8,0.08)' }}>
                {policy.severity === 'critical' ? <AlertTriangle size={14} style={{ color: '#F87171' }} /> :
                  <Shield size={14} style={{ color: policy.severity === 'high' ? '#FB923C' : '#FACC15' }} />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.85)' }}>{policy.name}</span>
                  <span className="text-[9px] font-medium px-1.5 py-0.5 rounded"
                    style={{ background: policy.severity === 'critical' ? 'rgba(239,68,68,0.1)' : policy.severity === 'high' ? 'rgba(249,115,22,0.1)' : 'rgba(234,179,8,0.1)', color: policy.severity === 'critical' ? '#F87171' : policy.severity === 'high' ? '#FB923C' : '#FACC15' }}>
                    {policy.severity}
                  </span>
                </div>
                <p className="text-[11px] mb-2" style={{ color: 'rgba(255,255,255,0.3)' }}>{policy.description}</p>
                <div className="flex gap-1.5 flex-wrap">
                  {policy.actions.map((action) => (
                    <span key={action} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.3)' }}>
                      {action}
                    </span>
                  ))}
                </div>
              </div>
              <button onClick={() => toggle(policy.id)}
                className="relative w-9 h-5 rounded-full transition-all shrink-0 mt-1"
                style={{ background: policy.enabled ? 'rgba(59,130,246,0.3)' : 'rgba(255,255,255,0.08)' }}>
                <motion.div className="absolute top-0.5 w-4 h-4 rounded-full"
                  animate={{ left: policy.enabled ? 18 : 2, background: policy.enabled ? '#3B82F6' : 'rgba(255,255,255,0.3)' }}
                  transition={{ type: 'spring', stiffness: 300, damping: 25 }} />
              </button>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
