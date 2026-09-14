import React, { useState } from 'react';
import { Globe, Server, ShieldCheck, Search, Database } from 'lucide-react';
import { Endpoint, ScanState } from '../types';
import { PlainEnglishBanner } from './PlainEnglishBanner';

interface AttackSurfaceViewProps {
  scanState: ScanState | null;
}

export const AttackSurfaceView: React.FC<AttackSurfaceViewProps> = ({ scanState }) => {
  const [filterMethod, setFilterMethod] = useState<string>('all');
  const [search, setSearch] = useState<string>('');

  const endpoints: Endpoint[] = scanState?.endpoints || [];
  const technologies: string[] = scanState?.technologies || [];

  const filteredEndpoints = endpoints.filter(ep => {
    const epMethod = (ep?.method || 'GET').toUpperCase();
    const targetFilter = (filterMethod || 'all').toUpperCase();
    const matchesMethod = filterMethod === 'all' || epMethod === targetFilter;
    const epPath = (ep?.path || '').toLowerCase();
    const epUrl = (ep?.url || '').toLowerCase();
    const term = (search || '').toLowerCase();
    const params = ep?.parameters || [];
    const matchesSearch = epPath.includes(term) ||
                          epUrl.includes(term) ||
                          params.some(p => (p || '').toLowerCase().includes(term));
    return matchesMethod && matchesSearch;
  });

  const getMethodBadge = (method: string) => {
    switch ((method || 'GET').toUpperCase()) {
      case 'GET':
        return 'bg-sky-950 text-sky-300 border-sky-800';
      case 'POST':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'PUT':
      case 'PATCH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'DELETE':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 font-sans w-full max-w-full min-w-0">
      
      {/* Overview Info Banner */}
      <PlainEnglishBanner
        title="What is your Attack Surface?"
        summary="Think of your website as a building: your Attack Surface is a map of every single front door, back door, window, form, and API endpoint that connects to the internet. If an attacker wants to break in, they must enter through one of these doors."
        points={[
          {
            label: "Discovered Doors (Endpoints)",
            desc: "Every web page, login form, search box, and API link discovered and tested by the reconnaissance AI bot."
          },
          {
            label: "Input Parameters (Keyholes)",
            desc: "Specific input fields (like username, search, or id) where user data is processed by your database and server."
          },
          {
            label: "Detected Software (Tech Stack)",
            desc: "The underlying software and frameworks running your site (e.g. Node.js, Express, React, PostgreSQL)."
          }
        ]}
      />

      {/* Surface Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-1">
          <div className="flex items-center space-x-2 text-sky-400 text-xs font-mono font-bold uppercase">
            <Globe className="w-4 h-4" />
            <span>Discovered Pages & Doors</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white pt-1">
            {endpoints.length}
          </div>
          <p className="text-[11px] text-slate-300">Total web routes & API endpoints mapped</p>
        </div>

        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-1">
          <div className="flex items-center space-x-2 text-emerald-300 text-xs font-mono font-bold uppercase">
            <Server className="w-4 h-4" />
            <span>Detected Technologies</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white pt-1">
            {technologies.length}
          </div>
          <p className="text-[11px] text-slate-300">Frameworks, databases, and servers</p>
        </div>

        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-1">
          <div className="flex items-center space-x-2 text-cyan-300 text-xs font-mono font-bold uppercase">
            <ShieldCheck className="w-4 h-4" />
            <span>Input Keyholes Tested</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white pt-1">
            {endpoints.reduce((acc, ep) => acc + (ep.parameters?.length || 0), 0)}
          </div>
          <p className="text-[11px] text-slate-300">Query & body parameters fuzzed for injection</p>
        </div>
      </div>

      {/* Software Stack Detected */}
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-sky-200 flex items-center space-x-2">
          <Database className="w-4 h-4 text-sky-400" />
          <span>Fingerprinted Technology Components</span>
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          The Red Team bot automatically fingerprints your server software to identify potential known version vulnerabilities:
        </p>
        <div className="flex flex-wrap gap-2 pt-1">
          {technologies.map((tech, idx) => (
            <div key={idx} className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-[#061021] border border-[#162f59] text-xs font-mono text-sky-200">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              <span>{tech}</span>
            </div>
          ))}
          {technologies.length === 0 && (
            <span className="text-xs text-slate-400">No technology fingerprints detected yet. Run a scan to discover.</span>
          )}
        </div>
      </div>

      {/* Endpoints Table Container */}
      <div className="bg-[#071326]/90 border border-[#162f55] rounded-2xl p-5 shadow-lg shadow-black/30 backdrop-blur-md space-y-4 w-full max-w-full min-w-0">
        
        {/* Table Filter / Search Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#142d54]">
          <div className="flex items-center space-x-1.5 bg-[#030915] p-1 rounded-xl border border-[#122340]">
            {['all', 'GET', 'POST', 'PUT', 'DELETE'].map(m => (
              <button
                key={m}
                onClick={() => setFilterMethod(m)}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold uppercase transition-all duration-150 cursor-pointer ${
                  filterMethod === m
                    ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-white shadow-md shadow-sky-500/25 ring-1 ring-sky-300/40'
                    : 'text-slate-400 hover:text-white hover:bg-[#0e2142]'
                }`}
              >
                {m}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search door path or param..."
              className="w-full bg-[#030915] border border-[#183561] focus:border-sky-400 rounded-xl pl-8 pr-3 py-1.5 text-xs text-sky-200 focus:outline-none font-mono shadow-inner placeholder-slate-500 transition-colors"
            />
          </div>
        </div>

        {/* Endpoints Table */}
        <div className="overflow-x-auto w-full max-w-full">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#162f59] text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="pb-3 px-2">Method</th>
                <th className="pb-3 px-2">Door / Path (URL)</th>
                <th className="pb-3 px-2">Tested Parameters</th>
                <th className="pb-3 px-2">Auth Gate</th>
                <th className="pb-3 px-2 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#102444] text-slate-200">
              {filteredEndpoints.map((ep, idx) => (
                <tr key={idx} className="hover:bg-[#08152b] transition-colors">
                  <td className="py-3 px-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getMethodBadge(ep.method)}`}>
                      {ep.method}
                    </span>
                  </td>
                  <td className="py-3 px-2 font-bold text-sky-200 break-all">
                    {ep.path}
                    <div className="text-[10px] text-slate-400 font-normal truncate max-w-sm">
                      {ep.url}
                    </div>
                  </td>
                  <td className="py-3 px-2">
                    <div className="flex flex-wrap gap-1">
                      {ep.parameters && ep.parameters.length > 0 ? (
                        ep.parameters.map((p, pIdx) => (
                          <span key={pIdx} className="px-1.5 py-0.5 rounded bg-[#061021] border border-[#162f59] text-[10px] text-cyan-300">
                            {p}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-400 text-[10px]">none (static route)</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-semibold ${
                      ep.auth_required
                        ? 'bg-amber-950/60 text-amber-300 border border-amber-800'
                        : 'bg-sky-950/60 text-sky-300 border border-sky-800'
                    }`}>
                      {ep.auth_required ? 'Password Protected' : 'Public Door'}
                    </span>
                  </td>
                  <td className="py-3 px-2 text-right">
                    <span className="text-emerald-400 font-bold text-[11px]">
                      {ep.status_code || 200} OK
                    </span>
                  </td>
                </tr>
              ))}

              {filteredEndpoints.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400 font-sans">
                    No matching attack surface endpoints found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>

    </div>
  );
};
export default AttackSurfaceView;
