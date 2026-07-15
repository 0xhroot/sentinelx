import { useState } from 'react';
import { motion } from 'framer-motion';
import { BrainCircuit, Search, Globe, FileCode, Shield, Bug } from 'lucide-react';

const tabs = [
  { id: 'iocs', label: 'IoCs', icon: Globe },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: Shield },
  { id: 'yara', label: 'YARA Rules', icon: FileCode },
  { id: 'sigma', label: 'Sigma Rules', icon: Bug },
];

const mockIocs = [
  { type: 'hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', severity: 'high', source: 'threat-intel' },
  { type: 'ip', value: '185.220.101.42', severity: 'critical', source: 'tor-exit' },
  { type: 'domain', value: 'malware-c2.evil.com', severity: 'critical', source: 'osint' },
  { type: 'hash', value: 'a1b2c3d4e5f6789012345678901234567890abcd', severity: 'medium', source: 'sandbox' },
];

const mockMitre = [
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', count: 12 },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence', count: 8 },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', count: 15 },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', count: 5 },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', count: 3 },
];

export default function Intelligence() {
  const [activeTab, setActiveTab] = useState('iocs');
  const [search, setSearch] = useState('');

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-1 p-0.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium transition-all"
              style={{
                background: activeTab === tab.id ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: activeTab === tab.id ? '#60A5FA' : 'rgba(255,255,255,0.35)',
              }}>
              <Icon size={12} /> {tab.label}
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-2 h-9 px-3 rounded-lg sx-input max-w-xs">
        <Search size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
        <input type="text" placeholder="Search intelligence..." value={search} onChange={(e) => setSearch(e.target.value)}
          className="bg-transparent border-none outline-none text-xs flex-1" style={{ color: 'rgba(255,255,255,0.87)' }} />
      </div>

      {activeTab === 'iocs' && (
        <div className="space-y-1.5">
          {mockIocs.filter((i) => !search || i.value.toLowerCase().includes(search.toLowerCase())).map((ioc, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              className="sx-card p-3 flex items-center gap-3">
              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                style={{ background: ioc.type === 'hash' ? 'rgba(139,92,246,0.1)' : ioc.type === 'ip' ? 'rgba(59,130,246,0.1)' : 'rgba(6,182,212,0.1)',
                  color: ioc.type === 'hash' ? '#A78BFA' : ioc.type === 'ip' ? '#60A5FA' : '#22D3EE' }}>
                {ioc.type.toUpperCase()}
              </span>
              <span className="font-mono text-xs flex-1" style={{ color: 'rgba(255,255,255,0.6)' }}>{ioc.value}</span>
              <span className={`sx-badge-${ioc.severity === 'critical' ? 'critical' : ioc.severity === 'high' ? 'high' : 'medium'}`}>
                {ioc.severity}
              </span>
              <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.2)' }}>{ioc.source}</span>
            </motion.div>
          ))}
        </div>
      )}

      {activeTab === 'mitre' && (
        <div className="space-y-1.5">
          {mockMitre.filter((m) => !search || m.name.toLowerCase().includes(search.toLowerCase())).map((technique, i) => (
            <motion.div key={technique.id} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              className="sx-card p-3 flex items-center gap-3">
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(59,130,246,0.1)', color: '#60A5FA' }}>
                {technique.id}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>{technique.name}</p>
                <p className="text-[10px]" style={{ color: 'rgba(255,255,255,0.25)' }}>{technique.tactic}</p>
              </div>
              <span className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.3)' }}>{technique.count} hits</span>
            </motion.div>
          ))}
        </div>
      )}

      {(activeTab === 'yara' || activeTab === 'sigma') && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center">
            <BrainCircuit size={32} className="mx-auto mb-3" style={{ color: 'rgba(255,255,255,0.06)' }} />
            <p className="text-sm" style={{ color: 'rgba(255,255,255,0.2)' }}>
              {activeTab === 'yara' ? 'YARA rules' : 'Sigma rules'} will appear here
            </p>
            <p className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.12)' }}>
              Load rules via the Intelligence API
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
