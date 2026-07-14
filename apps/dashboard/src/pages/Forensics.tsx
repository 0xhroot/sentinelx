import { useState, useEffect } from 'react';
import { fetchForensics } from '../api';
import { ForensicSnapshot } from '../types';

export default function Forensics() {
  const [snapshot, setSnapshot] = useState<ForensicSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchForensics().then(setSnapshot).catch((e) => setError(String(e)));
  }, []);

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load forensics data: {error}
        </div>
      )}
      {snapshot ? (
        <>
          <div className="card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">{snapshot.hostname}</h3>
              <span className="text-xs text-slate-400">
                {new Date(snapshot.timestamp).toLocaleString()}
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-800/40 rounded-lg p-3">
                <p className="text-xs text-slate-500">Kernel</p>
                <p className="text-sm font-medium text-slate-200 mt-0.5 font-mono">{snapshot.kernel_version}</p>
              </div>
              <div className="bg-slate-800/40 rounded-lg p-3">
                <p className="text-xs text-slate-500">Processes</p>
                <p className="text-sm font-medium text-blue-400 mt-0.5">{snapshot.processes.length}</p>
              </div>
              <div className="bg-slate-800/40 rounded-lg p-3">
                <p className="text-xs text-slate-500">Modules</p>
                <p className="text-sm font-medium text-purple-400 mt-0.5">{snapshot.modules.length}</p>
              </div>
              <div className="bg-slate-800/40 rounded-lg p-3">
                <p className="text-xs text-slate-500">Connections</p>
                <p className="text-sm font-medium text-cyan-400 mt-0.5">{snapshot.connections.length}</p>
              </div>
            </div>
          </div>

          {snapshot.threats.length > 0 && (
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">
                Threats ({snapshot.threats.length})
              </h3>
              <div className="space-y-2">
                {snapshot.threats.map((threat) => (
                  <div
                    key={threat.id}
                    className="flex items-start gap-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg"
                  >
                    <svg className="w-4 h-4 text-red-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    <div>
                      <p className="text-sm font-medium text-slate-200">{threat.title}</p>
                      <p className="text-xs text-slate-400 mt-0.5">{threat.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {snapshot.hooks.length > 0 && (
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">
                Hooks Detected ({snapshot.hooks.length})
              </h3>
              <div className="space-y-2">
                {snapshot.hooks.map((hook, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 bg-slate-800/40 rounded-lg border border-slate-700/30">
                    <span className="text-xs font-mono text-slate-300">{hook.hook_type}</span>
                    <span className="text-xs text-slate-500">0x{hook.address.toString(16)}</span>
                    {hook.symbol && <span className="text-xs text-blue-400">{hook.symbol}</span>}
                    {hook.module && <span className="text-xs text-slate-500">[{hook.module}]</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {snapshot.open_files.length > 0 && (
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">
                Open Files ({snapshot.open_files.length})
              </h3>
              <div className="max-h-60 overflow-y-auto space-y-1">
                {snapshot.open_files.slice(0, 50).map((file, i) => (
                  <div key={i} className="text-xs font-mono text-slate-400 py-0.5">
                    {file}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="card flex items-center justify-center h-64 text-slate-500">
          Loading forensics data...
        </div>
      )}
    </div>
  );
}
