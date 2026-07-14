import { useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { fetchStatus, runScan } from '../api';
import { StatusResponse } from '../types';

export default function Header() {
  const location = useLocation();
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [scanning, setScanning] = useState(false);

  const pageTitle: Record<string, string> = {
    '/': 'Overview',
    '/threats': 'Threats',
    '/timeline': 'Timeline',
    '/processes': 'Processes',
    '/modules': 'Kernel Modules',
    '/network': 'Network',
    '/kernel': 'Kernel Integrity',
    '/memory': 'Memory',
    '/forensics': 'Forensics',
    '/settings': 'Settings',
  };

  useEffect(() => {
    fetchStatus().then(setStatus).catch(() => {});
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      await runScan();
    } catch {
    } finally {
      setScanning(false);
    }
  };

  return (
    <header className="flex items-center justify-between px-6 py-4 bg-slate-900/40 border-b border-slate-700/50">
      <div>
        <h2 className="text-xl font-semibold text-white">
          {pageTitle[location.pathname] || 'SentinelX'}
        </h2>
        {status && (
          <p className="text-sm text-slate-400">
            {status.detector_count} detector{status.detector_count !== 1 ? 's' : ''} active
            &middot; {status.metrics.scans_completed} scans completed
          </p>
        )}
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm">
          {status ? (
            <>
              <div className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-green-400">Running</span>
            </>
          ) : (
            <>
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-red-400">Disconnected</span>
            </>
          )}
        </div>

        <button
          onClick={handleScan}
          disabled={scanning}
          className="btn-primary text-sm disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {scanning ? (
            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          ) : (
            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
          )}
          {scanning ? 'Scanning...' : 'Run Scan'}
        </button>
      </div>
    </header>
  );
}
