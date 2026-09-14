import React, { useState, useEffect } from 'react';
import {
  GitCommit,
  GitCompare,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  History,
  ShieldCheck,
  Clock,
  Code,
  FileCode,
  Layers,
} from 'lucide-react';
import { VersionComparisonResult, ScanState, Finding } from '../types';
import { safeFetchJson } from '../lib/safeFetch';

interface HistoryComparisonViewProps {
  scanState: ScanState | null;
}

export const HistoryComparisonView: React.FC<HistoryComparisonViewProps> = ({ scanState }) => {
  const [loading, setLoading] = useState(false);
  const [diffResult, setDiffResult] = useState<VersionComparisonResult | null>(null);
  const [selectedTab, setSelectedTab] = useState<'all' | 'new' | 'persistent' | 'resolved' | 'regressed' | 'not_detected'>('all');

  const projectId = scanState?.project_id || 'proj-shop-app';
  const currentVersionId = scanState?.version_id || 'ver-2';
  const currentProjectHash = scanState?.project_hash || 'sha256-current-hash';

  const runComparison = async () => {
    setLoading(true);
    try {
      const res = await safeFetchJson<{ success?: boolean; diff?: VersionComparisonResult }>('/api/projects/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          currentVersionId,
          currentProjectHash,
          currentFindings: scanState?.findings || [],
        }),
      });

      if (res.success && res.data?.diff) {
        setDiffResult(res.data.diff);
      }
    } catch (e) {
      console.error('Failed to compare project versions:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runComparison();
  }, [scanState?.scan_id, scanState?.project_hash]);

  const newFindings = diffResult?.new_findings || [];
  const persistentFindings = diffResult?.persistent_findings || [];
  const resolvedFindings = diffResult?.resolved_findings || [];
  const regressedFindings = diffResult?.regressed_findings || [];
  const notDetectedFindings = diffResult?.not_detected_findings || [];

  return (
    <div className="space-y-6 font-sans w-full max-w-full min-w-0">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl w-full min-w-0">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700">
              <GitCompare className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Project Security History & Version Diff
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Deterministic SHA-256 version tracking • Multi-scan diffing • Regression analysis
              </p>
            </div>
          </div>

          <button
            onClick={runComparison}
            disabled={loading}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition flex items-center gap-2 cursor-pointer shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Re-compare Versions
          </button>
        </div>

        {/* Version Comparison Card */}
        <div className="mt-5 pt-5 border-t border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" /> Previous Scan Baseline
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800">
                {diffResult?.previous_version?.version_id || 'ver-1'}
              </span>
            </div>
            <div className="text-xs font-mono text-slate-300">
              SHA: {(diffResult?.previous_version?.project_hash || '9a8b7c6d5e4f3a2b').substring(0, 16)}...
            </div>
            <div className="text-xs text-slate-400">
              Baseline Confirmed Vulnerabilities: <span className="text-slate-200 font-bold">{diffResult?.summary?.total_previous_confirmed ?? 0}</span>
            </div>
          </div>

          <div className="p-4 bg-slate-950/70 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-emerald-400 uppercase flex items-center gap-1.5">
                <GitCommit className="w-3.5 h-3.5 text-emerald-400" /> Current Build Under Audit
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                {diffResult?.current_version?.version_id || currentVersionId}
              </span>
            </div>
            <div className="text-xs font-mono text-slate-300">
              SHA: {(currentProjectHash || 'sha256-current').substring(0, 16)}...
            </div>
            <div className="text-xs text-slate-400">
              Current Confirmed Vulnerabilities: <span className="text-slate-200 font-bold">{diffResult?.summary?.total_current_confirmed ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">New Flaws</div>
          <div className="text-2xl font-bold text-red-400 mt-2">{newFindings.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Found in current version</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Persistent Flaws</div>
          <div className="text-2xl font-bold text-amber-400 mt-2">{persistentFindings.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Present across versions</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Resolved / Patched</div>
          <div className="text-2xl font-bold text-emerald-400 mt-2">{resolvedFindings.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Fixed in current version</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Regressions</div>
          <div className="text-2xl font-bold text-rose-400 mt-2">{regressedFindings.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Reintroduced flaws</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 font-medium">Not Detected</div>
          <div className="text-2xl font-bold text-sky-400 mt-2">{notDetectedFindings.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">No vulnerability detected</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 p-1.5 bg-[#071326]/90 border border-[#162f55] rounded-2xl overflow-x-auto scrollbar-none shadow-lg shadow-black/30 backdrop-blur-md">
        <button
          onClick={() => setSelectedTab('all')}
          className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 whitespace-nowrap cursor-pointer ${
            selectedTab === 'all'
              ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-white shadow-md shadow-sky-500/25 ring-1 ring-sky-300/40'
              : 'text-slate-400 hover:text-white hover:bg-[#0e2142]'
          }`}
        >
          All Diffs ({newFindings.length + persistentFindings.length + resolvedFindings.length + regressedFindings.length + notDetectedFindings.length})
        </button>
        <button
          onClick={() => setSelectedTab('new')}
          className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            selectedTab === 'new'
              ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30 ring-1 ring-rose-300/50'
              : 'text-rose-400 hover:text-rose-200 hover:bg-rose-950/40'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>New ({newFindings.length})</span>
        </button>
        <button
          onClick={() => setSelectedTab('persistent')}
          className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            selectedTab === 'persistent'
              ? 'bg-amber-500 text-slate-950 shadow-md shadow-amber-500/30 ring-1 ring-amber-300/50'
              : 'text-amber-400 hover:text-amber-200 hover:bg-amber-950/40'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Persistent ({persistentFindings.length})</span>
        </button>
        <button
          onClick={() => setSelectedTab('resolved')}
          className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            selectedTab === 'resolved'
              ? 'bg-emerald-500 text-white shadow-md shadow-emerald-500/30 ring-1 ring-emerald-300/50'
              : 'text-emerald-400 hover:text-emerald-200 hover:bg-emerald-950/40'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Resolved ({resolvedFindings.length})</span>
        </button>
        {regressedFindings.length > 0 && (
          <button
            onClick={() => setSelectedTab('regressed')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
              selectedTab === 'regressed'
                ? 'bg-rose-600 text-white shadow-md shadow-rose-600/30 ring-1 ring-rose-400/50'
                : 'text-rose-400 hover:text-rose-200 hover:bg-rose-950/40'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Regressed ({regressedFindings.length})</span>
          </button>
        )}
        <button
          onClick={() => setSelectedTab('not_detected')}
          className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
            selectedTab === 'not_detected'
              ? 'bg-sky-500 text-slate-950 shadow-md shadow-sky-500/30 ring-1 ring-sky-300/50'
              : 'text-sky-400 hover:text-sky-200 hover:bg-sky-950/40'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Not Detected ({notDetectedFindings.length})</span>
        </button>
      </div>

      {/* Diff Findings List */}
      <div className="space-y-3">
        {/* NEW FINDINGS */}
        {(selectedTab === 'all' || selectedTab === 'new') && newFindings.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" /> Newly Introduced Vulnerabilities
            </h3>
            {newFindings.map((f, i) => (
              <div key={i} className="bg-slate-900 border border-red-500/30 rounded-xl p-4 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-sm">{f.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30">
                    NEW IN CURRENT VERSION
                  </span>
                </div>
                <p className="text-xs text-slate-400">{f.description || f.plain_english_summary}</p>
                <div className="text-[11px] text-slate-500 font-mono">Location: {f.affected_endpoint || f.file}</div>
              </div>
            ))}
          </div>
        )}

        {/* PERSISTENT FINDINGS */}
        {(selectedTab === 'all' || selectedTab === 'persistent') && persistentFindings.length > 0 && (
          <div className="space-y-2 pt-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5" /> Persistent Vulnerabilities (Still Present)
            </h3>
            {persistentFindings.map((f, i) => (
              <div key={i} className="bg-slate-900 border border-amber-500/30 rounded-xl p-4 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-sm">{f.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    STILL PRESENT ACROSS BUILDS
                  </span>
                </div>
                <p className="text-xs text-slate-400">{f.description || f.plain_english_summary}</p>
                <div className="text-[11px] text-slate-500 font-mono">Location: {f.affected_endpoint || f.file}</div>
              </div>
            ))}
          </div>
        )}

        {/* RESOLVED FINDINGS */}
        {(selectedTab === 'all' || selectedTab === 'resolved') && resolvedFindings.length > 0 && (
          <div className="space-y-2 pt-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5" /> Resolved Vulnerabilities (Remediated)
            </h3>
            {resolvedFindings.map((f, i) => (
              <div key={i} className="bg-slate-900 border border-emerald-500/30 rounded-xl p-4 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-sm">{f.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    RESOLVED / PATCHED
                  </span>
                </div>
                <p className="text-xs text-slate-400">{f.plain_english_summary || f.description}</p>
                <div className="text-[11px] text-slate-500 font-mono">Location: {f.affected_endpoint || f.file}</div>
              </div>
            ))}
          </div>
        )}

        {/* REGRESSED FINDINGS */}
        {(selectedTab === 'all' || selectedTab === 'regressed') && regressedFindings.length > 0 && (
          <div className="space-y-2 pt-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" /> Regressed Vulnerabilities (Reintroduced)
            </h3>
            {regressedFindings.map((f, i) => (
              <div key={i} className="bg-slate-900 border border-rose-500/30 rounded-xl p-4 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-sm">{f.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    REGRESSED IN CURRENT VERSION
                  </span>
                </div>
                <p className="text-xs text-slate-400">{f.plain_english_summary || f.description}</p>
                <div className="text-[11px] text-slate-500 font-mono">Location: {f.affected_endpoint || f.file}</div>
              </div>
            ))}
          </div>
        )}

        {/* NOT DETECTED IN CURRENT SCAN */}
        {(selectedTab === 'all' || selectedTab === 'not_detected') && notDetectedFindings.length > 0 && (
          <div className="space-y-2 pt-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-2">
              <ShieldCheck className="w-3.5 h-3.5" /> Not Detected in Current Scan
            </h3>
            {notDetectedFindings.map((item, i) => (
              <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-sm">{item.category} ({item.cwe})</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-500/10 text-sky-400 border border-sky-500/30">
                    {item.status_label}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{item.reason}</p>
              </div>
            ))}
          </div>
        )}

        {newFindings.length === 0 &&
          persistentFindings.length === 0 &&
          resolvedFindings.length === 0 &&
          notDetectedFindings.length === 0 && (
            <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-2xl">
              <Layers className="w-8 h-8 text-slate-500 mx-auto mb-2" />
              <div className="text-sm font-bold text-slate-200">No Historical Delta Detected</div>
              <div className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                Upload a second version or modify source files to see automated regression and diff tracking.
              </div>
            </div>
          )}
      </div>
    </div>
  );
};
