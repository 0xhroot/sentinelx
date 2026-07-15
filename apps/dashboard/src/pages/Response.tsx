import { useState } from 'react';
import { motion } from 'framer-motion';
import { Siren, Shield, Play, Square, AlertTriangle, CheckCircle, Clock, FileText } from 'lucide-react';

interface ResponseAction {
  id: string;
  name: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  lastRun?: string;
}

const actions: ResponseAction[] = [
  { id: 'isolate', name: 'Network Isolation', status: 'idle' },
  { id: 'kill', name: 'Kill Process', status: 'idle' },
  { id: 'quarantine', name: 'Quarantine File', status: 'idle' },
  { id: 'snapshot', name: 'Capture Snapshot', status: 'idle' },
  { id: 'block-ip', name: 'Block IP Address', status: 'idle' },
  { id: 'rotate-keys', name: 'Rotate Credentials', status: 'idle' },
];

const playbooks = [
  { id: 'pb-1', name: 'Ransomware Response', steps: ['Isolate', 'Snapshot', 'Block IOCs', 'Notify'], status: 'ready' },
  { id: 'pb-2', name: 'Data Exfiltration', steps: ['Block IP', 'Kill Process', 'Capture Logs', 'Escalate'], status: 'ready' },
  { id: 'pb-3', name: 'Rootkit Detection', steps: ['Snapshot', 'Integrity Check', 'Kernel Audit', 'Report'], status: 'ready' },
];

export default function Response() {
  const [actionList, setActionList] = useState(actions);
  const [dryRun, setDryRun] = useState(true);

  const runAction = (id: string) => {
    setActionList((prev) => prev.map((a) => a.id === id ? { ...a, status: 'running' as const } : a));
    setTimeout(() => {
      setActionList((prev) => prev.map((a) => a.id === id ? { ...a, status: 'completed' as const, lastRun: new Date().toISOString() } : a));
    }, 2000);
  };

  return (
    <div className="space-y-4">
      {/* Mode indicator */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[11px] font-medium"
          style={{ background: dryRun ? 'rgba(234,179,8,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${dryRun ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)'}`, color: dryRun ? '#FACC15' : '#F87171' }}>
          <AlertTriangle size={12} />
          {dryRun ? 'DRY RUN — No changes will be applied' : 'LIVE — Actions will be executed'}
        </div>
        <button onClick={() => setDryRun(!dryRun)}
          className="text-[11px] font-medium px-2.5 py-1.5 rounded-lg transition-all"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.5)' }}>
          Toggle Mode
        </button>
      </div>

      {/* Manual Actions */}
      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Manual Response Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {actionList.map((action, i) => (
            <motion.div key={action.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="p-3 rounded-xl flex items-center gap-3"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
              <div className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
                style={{ background: action.status === 'completed' ? 'rgba(34,197,94,0.1)' : action.status === 'running' ? 'rgba(59,130,246,0.1)' : action.status === 'failed' ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.03)' }}>
                {action.status === 'completed' ? <CheckCircle size={14} style={{ color: '#4ADE80' }} /> :
                  action.status === 'running' ? <Clock size={14} style={{ color: '#60A5FA' }} /> :
                    <Shield size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>{action.name}</p>
                {action.lastRun && (
                  <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.2)' }}>
                    Last: {new Date(action.lastRun).toLocaleTimeString()}
                  </p>
                )}
              </div>
              <button onClick={() => runAction(action.id)} disabled={action.status === 'running'}
                className="w-7 h-7 flex items-center justify-center rounded-lg transition-all"
                style={{
                  background: action.status === 'running' ? 'rgba(59,130,246,0.1)' : 'rgba(255,255,255,0.04)',
                  color: action.status === 'running' ? '#60A5FA' : 'rgba(255,255,255,0.4)',
                  cursor: action.status === 'running' ? 'not-allowed' : 'pointer',
                }}>
                {action.status === 'running' ? <Square size={11} /> : <Play size={11} />}
              </button>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Playbooks */}
      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Automated Playbooks
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {playbooks.map((pb, i) => (
            <motion.div key={pb.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="p-4 rounded-xl cursor-pointer transition-all"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(59,130,246,0.15)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.04)'; }}>
              <div className="flex items-center gap-2 mb-3">
                <Siren size={14} style={{ color: '#F97316' }} />
                <span className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.85)' }}>{pb.name}</span>
              </div>
              <div className="space-y-1">
                {pb.steps.map((step, j) => (
                  <div key={j} className="flex items-center gap-2 text-[10px]">
                    <span className="font-mono w-4" style={{ color: 'rgba(255,255,255,0.15)' }}>{j + 1}</span>
                    <span style={{ color: 'rgba(255,255,255,0.4)' }}>{step}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(34,197,94,0.08)', color: '#4ADE80' }}>
                  Ready
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Audit log */}
      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Response Audit Log
        </h3>
        <div className="space-y-1 font-mono text-[11px] max-h-[200px] overflow-y-auto" style={{ color: 'rgba(255,255,255,0.3)' }}>
          <div className="flex items-center gap-2 py-0.5">
            <span style={{ color: 'rgba(255,255,255,0.15)' }}>14:32:01</span>
            <FileText size={10} style={{ color: 'rgba(255,255,255,0.15)' }} />
            <span>DRY_RUN action=isolate target=10.0.1.15 result=simulated</span>
          </div>
          <div className="flex items-center gap-2 py-0.5">
            <span style={{ color: 'rgba(255,255,255,0.15)' }}>14:28:44</span>
            <FileText size={10} style={{ color: 'rgba(255,255,255,0.15)' }} />
            <span>DRY_RUN action=kill_process target=pid:3847 result=simulated</span>
          </div>
          <div className="flex items-center gap-2 py-0.5">
            <span style={{ color: 'rgba(255,255,255,0.15)' }}>14:15:22</span>
            <FileText size={10} style={{ color: 'rgba(255,255,255,0.15)' }} />
            <span>PLAYBOOK triggered=name=ransomware_response auto=false</span>
          </div>
        </div>
      </div>
    </div>
  );
}
