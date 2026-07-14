import { useState, useEffect } from 'react';
import { fetchDetectors, fetchStatus } from '../api';
import { StatusResponse, DetectorInfo } from '../types';

export default function Settings() {
  const [detectors, setDetectors] = useState<DetectorInfo[]>([]);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [notifications, setNotifications] = useState(true);
  const [autoScan, setAutoScan] = useState(true);
  const [scanInterval, setScanInterval] = useState('300');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDetectors().then((d) => setDetectors(d.detectors)).catch((e) => setError(String(e)));
    fetchStatus().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  return (
    <div className="space-y-6 max-w-3xl">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load data: {error}
        </div>
      )}
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-4">System Information</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-800/40 rounded-lg p-4">
            <p className="text-xs text-slate-500">Status</p>
            <div className="flex items-center gap-2 mt-1">
              <div className={`w-2 h-2 rounded-full ${status ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm font-medium text-slate-200">
                {status ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
          <div className="bg-slate-800/40 rounded-lg p-4">
            <p className="text-xs text-slate-500">Scans Completed</p>
            <p className="text-sm font-medium text-slate-200 mt-0.5">
              {status?.metrics.scans_completed ?? 0}
            </p>
          </div>
          <div className="bg-slate-800/40 rounded-lg p-4">
            <p className="text-xs text-slate-500">Threats Detected</p>
            <p className="text-sm font-medium text-slate-200 mt-0.5">
              {status?.metrics.threats_detected ?? 0}
            </p>
          </div>
          <div className="bg-slate-800/40 rounded-lg p-4">
            <p className="text-xs text-slate-500">Events Processed</p>
            <p className="text-sm font-medium text-slate-200 mt-0.5">
              {status?.metrics.events_processed?.toLocaleString() ?? '0'}
            </p>
          </div>
        </div>
      </div>

      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Configuration</h3>
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-200">Desktop Notifications</p>
              <p className="text-xs text-slate-500 mt-0.5">Show desktop notifications for critical threats</p>
            </div>
            <button
              onClick={() => setNotifications(!notifications)}
              className={`relative w-11 h-6 rounded-full transition-colors ${notifications ? 'bg-blue-600' : 'bg-slate-700'}`}
            >
              <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${notifications ? 'translate-x-5' : ''}`} />
            </button>
          </div>

          <div className="border-t border-slate-700/50" />

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-200">Automatic Scanning</p>
              <p className="text-xs text-slate-500 mt-0.5">Run periodic system scans automatically</p>
            </div>
            <button
              onClick={() => setAutoScan(!autoScan)}
              className={`relative w-11 h-6 rounded-full transition-colors ${autoScan ? 'bg-blue-600' : 'bg-slate-700'}`}
            >
              <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${autoScan ? 'translate-x-5' : ''}`} />
            </button>
          </div>

          <div className="border-t border-slate-700/50" />

          <div>
            <p className="text-sm font-medium text-slate-200 mb-2">Scan Interval (seconds)</p>
            <select
              value={scanInterval}
              onChange={(e) => setScanInterval(e.target.value)}
              disabled={!autoScan}
              className="input-field max-w-xs disabled:opacity-50"
            >
              <option value="60">60 seconds</option>
              <option value="300">5 minutes</option>
              <option value="600">10 minutes</option>
              <option value="1800">30 minutes</option>
              <option value="3600">1 hour</option>
            </select>
          </div>
        </div>
      </div>

      <div className="card p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Active Detectors</h3>
        <div className="space-y-3">
          {detectors.map((detector) => (
            <div
              key={detector.name}
              className="flex items-center justify-between p-4 bg-slate-800/40 rounded-lg border border-slate-700/30"
            >
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
                <div>
                  <p className="text-sm font-medium text-slate-200">{detector.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{detector.description}</p>
                </div>
              </div>
              <div className="text-right">
                <span className="badge bg-green-500/10 text-green-400 border border-green-500/30">
                  {detector.category}
                </span>
                <p className="text-xs text-slate-500 mt-1">Severity: {detector.severity}</p>
              </div>
            </div>
          ))}
          {detectors.length === 0 && (
            <div className="text-center py-8 text-slate-500 text-sm">
              No detector data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
