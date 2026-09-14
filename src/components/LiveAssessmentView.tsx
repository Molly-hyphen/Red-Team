import React, { useRef, useEffect } from 'react';
import { Terminal, ShieldAlert, Cpu, Activity, CheckCircle2, Play, ArrowRight, Info, Shield, Radio } from 'lucide-react';
import { ScanState, AgentInfo } from '../types';
import { PlainEnglishBanner } from './PlainEnglishBanner';

interface LiveAssessmentViewProps {
  scanState: ScanState | null;
  onSelectFinding?: (findingId: string) => void;
  onOpenLaunchModal: () => void;
}

export const LiveAssessmentView: React.FC<LiveAssessmentViewProps> = ({
  scanState,
  onOpenLaunchModal
}) => {
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [scanState?.events]);

  const getAgentRoleDescription = (role: string) => {
    switch (role) {
      case 'RootOrchestratorAgent':
        return { friendlyTitle: 'Red Team Leader', summary: 'Directs attack plan and assigns sub-tasks to specialized bots' };
      case 'ReconAgent':
        return { friendlyTitle: 'Attack Surface Scout', summary: 'Maps ports, web routes, and fingerprinted technologies' };
      case 'APIAgent':
        return { friendlyTitle: 'API & Parameter Fuzzer', summary: 'Probes inputs, parameters, and injection vectors' };
      case 'AuthorizationAgent':
        return { friendlyTitle: 'Privilege & IDOR Tester', summary: 'Checks broken access control and horizontal tenant leaks' };
      case 'WebAgent':
        return { friendlyTitle: 'Web Frontend Tester', summary: 'Audits HTML forms, client scripts, and XSS vulnerabilities' };
      case 'PerimeterAgent':
        return { friendlyTitle: 'Perimeter Leak Scout', summary: 'Discovers exposed backups, git repos, and sensitive config paths' };
      case 'NetworkAgent':
        return { friendlyTitle: 'Network & SSL Auditor', summary: 'Evaluates TLS ciphers, CORS policies, and security headers' };
      case 'AuthAgent':
        return { friendlyTitle: 'Auth & Brute-Force Auditor', summary: 'Tests rate limiting, credential stuffing, and session lockout' };
      case 'SourceAnalysisAgent':
        return { friendlyTitle: 'SAST Code Auditor', summary: 'Inspects code syntax for raw SQL injection and unparameterized sinks' };
      case 'SecretScannerAgent':
        return { friendlyTitle: 'Secrets Scanner', summary: 'Scans for hardcoded JWT keys, AWS tokens, and passwords' };
      case 'DependencyAuditorAgent':
        return { friendlyTitle: 'Dependency SCA Auditor', summary: 'Scans third-party packages for known CVEs and supply-chain flaws' };
      case 'CodeFlowAgent':
        return { friendlyTitle: 'Taint & Data-Flow Analyzer', summary: 'Traces untrusted inputs into system commands, file paths, and eval sinks' };
      case 'CryptoAuditAgent':
        return { friendlyTitle: 'Cryptography Auditor', summary: 'Identifies broken ciphers, weak hashing algorithms, and PRNG seeds' };
      case 'APIRouteAgent':
        return { friendlyTitle: 'API & GraphQL Schema Scout', summary: 'Extracts OpenAPI, Swagger, and GraphQL schema endpoints' };
      case 'PrivilegeEscalationAgent':
        return { friendlyTitle: 'Privilege Escalation Tester', summary: 'Tests broken function-level authorization and role boundary bypasses' };
      case 'SSRFHunterAgent':
        return { friendlyTitle: 'SSRF & Cloud Metadata Hunter', summary: 'Probes internal IP loopbacks and cloud instance metadata exfiltration' };
      case 'BusinessLogicAgent':
        return { friendlyTitle: 'Business Logic & Mass Assignment Auditor', summary: 'Tests parameter tampering, race conditions, and hidden field binding' };
      case 'ValidatorAgent':
        return { friendlyTitle: 'Proof-of-Concept Verifier', summary: 'Empirically executes exploit proofs to eliminate false alarms' };
      default:
        return { friendlyTitle: 'Security Agent', summary: 'Autonomous testing unit' };
    }
  };

  if (!scanState) {
    return (
      <div className="space-y-6 font-sans w-full max-w-full min-w-0">
        <PlainEnglishBanner
          title="What is the Live Red Team Stream?"
          summary="This is your live command center. Autonomous AI security agents work together like an elite ethical hacking team to inspect your website, find hidden security gaps, and verify vulnerabilities with proof."
          points={[
            {
              label: "Multi-Agent Attack Team",
              desc: "Specialized AI bots (Scouts, Parameter Fuzzers, Code Auditors) work simultaneously on different areas of your target."
            },
            {
              label: "Zero Guesswork",
              desc: "The Proof Validator agent tests every suspected flaw with safe payloads to eliminate false positives."
            },
            {
              label: "Real-Time Terminal",
              desc: "Live stream showing every request, discovered endpoint, and verified vulnerability as it happens."
            }
          ]}
        />

        <div className="flex flex-col items-center justify-center py-20 text-center px-4 bg-[#0a1832] border border-[#162f59] rounded-2xl p-8 shadow-xl w-full min-w-0">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-sky-400/20 via-cyan-500/30 to-blue-600/40 border border-sky-400/30 flex items-center justify-center mb-4 text-sky-300 shadow-xl shadow-sky-950/40">
            <Shield className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-slate-100 mb-1 tracking-tight">No Active Red Team Assessment</h3>
          <p className="text-xs text-slate-300 max-w-md mb-6 leading-relaxed">
            Ready to test? Launch an autonomous multi-agent red team scan on your website URL or codebase to uncover and verify vulnerabilities.
          </p>
          <button
            onClick={onOpenLaunchModal}
            className="flex items-center space-x-2 px-6 py-3 rounded-xl text-xs font-bold bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-cyan-400 text-white shadow-lg shadow-sky-500/30 ring-1 ring-sky-300/40 transition-all hover:scale-105 active:scale-95 cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>Launch Red Team Assessment</span>
          </button>
        </div>
      </div>
    );
  }

  const agentsList: AgentInfo[] = Object.values(scanState.agents);
  const validatedFindings = scanState.findings.filter(
    f => (f.status || (f.validation_status === 'validated' ? 'CONFIRMED' : 'POTENTIAL')) === 'CONFIRMED'
  );

  return (
    <div className="space-y-6 font-sans w-full max-w-full min-w-0">
      
      {/* Overview Info Banner */}
      <PlainEnglishBanner
        title="What is happening on this screen?"
        summary="Your autonomous Red Team agents are actively assessing the target. The Red Team Lead orchestrates tests across specialized scout and testing agents, while the live terminal shows their activity and verified findings in real time."
        points={[
          {
            label: "Left: Red Team Hierarchy",
            desc: "Shows which specialized AI bots are active and what specific security tests they are executing."
          },
          {
            label: "Right: Live Event Stream",
            desc: "The real-time log of HTTP requests, discovered pages, and confirmed vulnerabilities with proof."
          },
          {
            label: "Verified Proof",
            desc: "Every finding highlighted in red or amber has been empirically validated with real proof-of-concept."
          }
        ]}
      />

      {/* Target Status Banner */}
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-xl w-full min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-4 w-full min-w-0">
          <div className="space-y-1.5 min-w-0 max-w-full">
            <div className="flex items-center space-x-2.5 min-w-0">
              <span className="text-[11px] font-mono text-sky-400 font-bold uppercase tracking-wider shrink-0">TARGET ASSET</span>
              <h2 className="text-base font-bold font-mono text-white break-all">{scanState.target}</h2>
            </div>
            <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-300">
              <span className="px-2.5 py-0.5 rounded-lg bg-[#061021] border border-[#183561] font-mono text-sky-200 font-medium">
                Mode: {scanState.mode === 'black_box' ? 'Black Box (Outside-In)' : scanState.mode === 'white_box' ? 'White Box (Code Audit)' : 'Grey Box (Hybrid)'}
              </span>
              <span className="px-2.5 py-0.5 rounded-lg bg-[#061021] border border-[#183561] font-mono text-sky-200 font-medium">
                Depth: {scanState.depth === 'quick_surface' ? 'Quick Surface' : 'Deep Technical'}
              </span>
              <span>•</span>
              <span className="flex items-center space-x-1.5">
                <span>Status:</span>
                <span className={`font-mono font-bold uppercase ${scanState.status === 'completed' ? 'text-emerald-400' : 'text-cyan-400 animate-pulse'}`}>
                  {scanState.status}
                </span>
              </span>
              <span>•</span>
              <span>Started: <span className="text-slate-200 font-mono">{new Date(scanState.started_at).toLocaleTimeString()}</span></span>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="flex flex-wrap items-center gap-3">
            <div className={`px-4 py-2.5 rounded-xl border text-center min-w-[90px] sm:min-w-[100px] flex-1 sm:flex-initial ${
              validatedFindings.length === 0 && scanState.status === 'completed'
                ? 'bg-emerald-950/40 border-emerald-500/40'
                : 'bg-[#061021] border-[#183561]'
            }`}>
              <div className={`text-[10px] uppercase font-mono font-bold ${
                validatedFindings.length === 0 && scanState.status === 'completed'
                  ? 'text-emerald-300'
                  : 'text-rose-400'
              }`}>
                {validatedFindings.length === 0 && scanState.status === 'completed' ? 'Posture' : 'Verified Flaws'}
              </div>
              <div className={`text-xl font-bold font-mono mt-0.5 ${
                validatedFindings.length === 0 && scanState.status === 'completed'
                  ? 'text-emerald-400 text-sm py-1'
                  : 'text-rose-400'
              }`}>
                {validatedFindings.length === 0 && scanState.status === 'completed' ? 'RESILIENT' : validatedFindings.length}
              </div>
            </div>
            <div className="bg-[#061021] px-4 py-2.5 rounded-xl border border-[#183561] text-center min-w-[90px] sm:min-w-[100px] flex-1 sm:flex-initial">
              <div className="text-[10px] uppercase font-mono text-cyan-300 font-bold">Discovered Doors</div>
              <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">{scanState.endpoints.length}</div>
            </div>
            <div className="bg-[#061021] px-4 py-2.5 rounded-xl border border-[#183561] text-center min-w-[90px] sm:min-w-[100px] flex-1 sm:flex-initial">
              <div className="text-[10px] uppercase font-mono text-sky-400 font-bold">Agents Active</div>
              <div className="text-xl font-bold font-mono text-sky-400 mt-0.5">{agentsList.length || 1}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Architecture Pipeline Intelligence Card */}
      {(scanState.application_profile || scanState.test_plan || scanState.project_hash) && (
        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-4 shadow-xl text-xs space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#162f59]">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              <span className="font-mono font-bold text-sky-300 uppercase tracking-wider text-[11px]">
                Part 1 Architecture: Context-Aware Dynamic Testing Engine
              </span>
            </div>
            {scanState.project_hash && (
              <div className="font-mono text-[10px] text-slate-400 bg-[#061021] px-2.5 py-1 rounded-lg border border-[#183561]">
                Fingerprint (SHA-256): <span className="text-cyan-300 font-bold">{scanState.project_hash.substring(0, 16)}...</span>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {/* Step 1: Profile */}
            <div className="bg-[#061021] p-2.5 rounded-xl border border-[#183561]">
              <div className="text-[10px] uppercase font-mono text-slate-400 font-bold">1. Recon & Profiling</div>
              <div className="text-xs font-semibold text-white mt-1">
                {scanState.application_profile?.framework || 'Discovered Stack'}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Lang: {scanState.application_profile?.language || 'Multi'} • {scanState.application_profile?.dependencies?.length || 0} packages
              </div>
            </div>

            {/* Step 2: Attack Surface */}
            <div className="bg-[#061021] p-2.5 rounded-xl border border-[#183561]">
              <div className="text-[10px] uppercase font-mono text-slate-400 font-bold">2. Attack Surface</div>
              <div className="text-xs font-semibold text-teal-300 mt-1">
                {scanState.attack_surface?.attack_vectors?.length || scanState.endpoints.length} Entry Vectors
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Params: {scanState.attack_surface?.parameters?.length || 0} • Sinks: {scanState.attack_surface?.file_upload_sinks?.length || 0}
              </div>
            </div>

            {/* Step 3: Dynamic Planner */}
            <div className="bg-[#061021] p-2.5 rounded-xl border border-[#183561]">
              <div className="text-[10px] uppercase font-mono text-slate-400 font-bold">3. Dynamic Test Plan</div>
              <div className="text-xs font-semibold text-indigo-300 mt-1">
                {scanState.test_plan?.planned_tests?.length || 0} Relevant Tests
              </div>
              <div className="text-[11px] text-amber-400/90 mt-0.5">
                {scanState.test_plan?.total_gated_out_tests || 0} Irrelevant Categories Gated Out
              </div>
            </div>

            {/* Step 4: Hypotheses & Evidence */}
            <div className="bg-[#061021] p-2.5 rounded-xl border border-[#183561]">
              <div className="text-[10px] uppercase font-mono text-slate-400 font-bold">4. Validated Evidence</div>
              <div className="text-xs font-semibold text-emerald-300 mt-1">
                {scanState.hypotheses?.length || 0} Hypotheses Evaluated
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {validatedFindings.length} Confirmed Flaws • Zero Canned Inventions
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Grid: Multi-Agent Tree + Live Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 w-full min-w-0">
        
        {/* Left Col: Multi-Agent Orchestration Tree (5 cols) */}
        <div className="lg:col-span-5 space-y-4 w-full min-w-0">
          <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-md">
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#162f59]">
              <div className="flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-sky-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Red Team Agent Hierarchy
                </h3>
              </div>
              <span className="text-[10px] font-mono text-sky-300 bg-[#071329] px-2.5 py-0.5 rounded-lg border border-[#142d54]">
                Autonomous Agents
              </span>
            </div>

            {/* Tree items */}
            <div className="space-y-3">
              {/* Root Agent */}
              <div className="p-3.5 rounded-xl bg-[#061021] border border-sky-500/40 shadow-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${scanState.status === 'completed' ? 'bg-emerald-400' : 'bg-cyan-400 animate-ping'}`} />
                    <div>
                      <span className="text-xs font-bold text-sky-200 font-mono">RootOrchestratorAgent</span>
                      <span className="ml-2 text-[10px] px-1.5 py-0.2 rounded bg-sky-950 text-sky-200 font-sans font-semibold border border-sky-800">
                        Red Team Lead
                      </span>
                    </div>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-semibold ${
                    scanState.status === 'completed' 
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' 
                      : 'bg-sky-950 text-sky-300 border border-sky-800'
                  }`}>
                    {scanState.status === 'completed' ? 'COMPLETED' : 'COORDINATING'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 mt-1.5 leading-relaxed">
                  Analyzing target scope, directing attack vectors, and coordinating specialized bots.
                </p>
              </div>

              {/* Sub Agents */}
              {agentsList.filter(a => a.role !== 'RootOrchestratorAgent').map(agent => {
                const info = getAgentRoleDescription(agent.role);
                const isCompleted = agent.status === 'completed' || scanState.status === 'completed';
                return (
                  <div key={agent.agent_id} className="ml-4 pl-3 border-l-2 border-[#183561] relative">
                    <div className="p-3 rounded-xl bg-[#061021] border border-[#162f59] hover:border-sky-500/40 transition-colors space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${
                            isCompleted ? 'bg-emerald-400' :
                            agent.status === 'running' ? 'bg-amber-400 animate-pulse' : 'bg-slate-500'
                          }`} />
                          <span className="text-xs font-bold text-slate-200 font-mono">{agent.role}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#0b1c38] text-cyan-300 font-sans border border-[#183561]">
                            {info.friendlyTitle}
                          </span>
                        </div>
                        <span className={`text-[9px] uppercase font-mono px-1.5 py-0.5 rounded font-semibold ${
                          isCompleted ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                          agent.status === 'running' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {isCompleted ? 'completed' : agent.status}
                        </span>
                      </div>
                      
                      <p className="text-[11px] text-slate-300">{info.summary}</p>

                      {agent.current_task && (
                        <p className="text-[11px] text-sky-300 font-mono break-all pt-0.5">
                          &gt; {agent.current_task}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}

              {agentsList.length === 0 && (
                <div className="text-center py-6 text-xs text-slate-400">
                  Initializing agents...
                </div>
              )}
            </div>
          </div>

          {/* Attack Surface Summary Box */}
          <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-md">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-1 flex items-center justify-between">
              <span>Fingerprinted Software Stack</span>
            </h4>
            <p className="text-[11px] text-slate-300 mb-2">Technologies detected running on the target:</p>
            <div className="flex flex-wrap gap-1.5">
              {scanState.technologies.map((t, idx) => (
                <span key={idx} className="text-[11px] px-3 py-1 rounded-lg bg-[#061021] border border-[#183561] text-sky-300 font-mono">
                  {t}
                </span>
              ))}
              {scanState.technologies.length === 0 && (
                <span className="text-xs text-slate-400">Discovering tech stack...</span>
              )}
            </div>
          </div>
        </div>

        {/* Right Col: Live Event Terminal Stream (7 cols) */}
        <div className="lg:col-span-7 w-full min-w-0">
          <div className="bg-[#030814] border border-[#162f59] rounded-2xl shadow-xl overflow-hidden flex flex-col h-[540px] w-full min-w-0">
            
            {/* Terminal Header */}
            <div className="bg-[#071329] px-4 py-3 border-b border-[#162f59] flex items-center justify-between text-xs min-w-0 gap-2">
              <div className="flex items-center space-x-2 min-w-0">
                <div className="flex space-x-1.5 shrink-0">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                </div>
                <span className="font-mono text-slate-200 ml-2 font-semibold truncate">Red Team Live Stream & Activity Log</span>
              </div>
              <span className={`text-[10px] font-mono uppercase font-bold shrink-0 ${
                scanState.status === 'completed' ? 'text-emerald-400' : 'text-cyan-400 animate-pulse'
              }`}>
                {scanState.status === 'completed' ? '✔ FINISHED' : '● LIVE STREAM'}
              </span>
            </div>

            {/* Terminal Output */}
            <div className="p-4 overflow-y-auto font-mono text-xs space-y-2 flex-1 scrollbar-thin scrollbar-thumb-[#183561] break-words [overflow-wrap:anywhere] min-w-0">
              {scanState.events.map((evt) => {
                const time = new Date(evt.timestamp).toLocaleTimeString();
                
                if (evt.event_type === 'scan.started') {
                  return (
                    <div key={evt.event_id} className="text-sky-300 py-1 border-b border-[#12274b]">
                      <span className="text-slate-500">[{time}]</span> [ORCHESTRATOR] Initialized scan against <span className="underline font-bold text-white">{evt.payload.target}</span> in mode <span className="text-amber-300 font-bold">{evt.payload.mode}</span>
                    </div>
                  );
                }

                if (evt.event_type === 'project.fingerprinted') {
                  return (
                    <div key={evt.event_id} className="text-cyan-300 font-mono text-[11px] bg-cyan-950/30 p-2 rounded-xl border border-cyan-800/40">
                      <span className="text-slate-500">[{time}]</span> 🆔 [PROJECT IDENTITY & FINGERPRINT]: <span className="text-white font-bold">{evt.payload.project_hash?.substring(0, 16)}...</span> ({evt.payload.algorithm}) | Normalized Files: {evt.payload.normalized_files_count}
                    </div>
                  );
                }

                if (evt.event_type === 'recon.profile_generated') {
                  const prof = evt.payload.profile;
                  return (
                    <div key={evt.event_id} className="text-emerald-300 font-mono text-[11px] bg-emerald-950/30 p-2 rounded-xl border border-emerald-800/40">
                      <span className="text-slate-500">[{time}]</span> 🔍 [APPLICATION PROFILE]: Framework: <span className="text-white font-bold">{prof?.framework || 'Custom'}</span> | Language: {prof?.language} | Auth: {prof?.auth_mechanisms?.join(', ') || 'None'} | Routes: {prof?.routes_count}
                    </div>
                  );
                }

                if (evt.event_type === 'surface.mapped') {
                  const surface = evt.payload.attack_surface;
                  return (
                    <div key={evt.event_id} className="text-teal-300 font-mono text-[11px] bg-teal-950/30 p-2 rounded-xl border border-teal-800/40">
                      <span className="text-slate-500">[{time}]</span> 🎯 [ATTACK SURFACE MAPPED]: {surface?.attack_vectors?.length || 0} active vectors identified (Parameters: {surface?.parameters?.length || 0}, Sinks: {surface?.file_upload_sinks?.length || 0})
                    </div>
                  );
                }

                if (evt.event_type === 'test_plan.created') {
                  const plan = evt.payload.test_plan;
                  return (
                    <div key={evt.event_id} className="text-indigo-300 font-mono text-[11px] bg-indigo-950/30 p-2 rounded-xl border border-indigo-800/40">
                      <span className="text-slate-500">[{time}]</span> 📋 [DYNAMIC TEST PLAN]: Generated {plan?.planned_tests?.length || 0} relevant test requests | Gated out {plan?.total_gated_out_tests || 0} non-applicable test categories
                    </div>
                  );
                }

                if (evt.event_type === 'observation.recorded') {
                  const obs = evt.payload.observation;
                  return (
                    <div key={evt.event_id} className="text-slate-300 pl-3 py-0.5">
                      <span className="text-slate-500">[{time}]</span> 👁 [OBSERVATION]: <span className="text-sky-300 font-semibold">{obs?.category}</span> at <span className="text-slate-200">{obs?.target_location}</span>
                    </div>
                  );
                }

                if (evt.event_type === 'hypothesis.generated') {
                  const hyp = evt.payload.hypothesis;
                  return (
                    <div key={evt.event_id} className="text-amber-200 font-semibold bg-amber-950/20 p-2 rounded-xl border border-amber-800/30">
                      <span className="text-slate-500">[{time}]</span> 💡 [HYPOTHESIS FORMULATED]: Suspected <span className="text-amber-300 font-bold">{hyp?.suspected_flaw}</span> ({Math.round((hyp?.confidence || 0.5) * 100)}% confidence) &gt; Queued for Empirical PoC Validation
                    </div>
                  );
                }

                if (evt.event_type === 'agent.created' || evt.event_type === 'agent.started') {
                  return (
                    <div key={evt.event_id} className="text-slate-200 py-0.5">
                      <span className="text-slate-500">[{time}]</span> <span className="text-sky-300 font-bold">[{evt.payload.role || 'Agent'}]</span> {evt.payload.current_task || evt.payload.objective}
                    </div>
                  );
                }

                if (evt.event_type === 'tool.started') {
                  return (
                    <div key={evt.event_id} className="text-slate-300 pl-3">
                      <span className="text-slate-500">[{time}]</span> ⚙ <span className="text-sky-200 font-semibold">{evt.payload.tool_name}</span> &gt; {evt.payload.target}
                    </div>
                  );
                }

                if (evt.event_type === 'endpoint.discovered') {
                  return (
                    <div key={evt.event_id} className="text-emerald-400 pl-3">
                      <span className="text-slate-500">[{time}]</span> + Discovered door/route: <span className="text-slate-100">{evt.payload.url}</span>
                    </div>
                  );
                }

                if (evt.event_type === 'finding.created') {
                  const f = evt.payload.finding;
                  return (
                    <div key={evt.event_id} className="text-amber-300 font-semibold bg-amber-950/30 p-2 rounded-xl border border-amber-800/40">
                      <span className="text-slate-500">[{time}]</span> ⚠ [SUSPECTED FLAW FOUND]: [{(f?.severity || 'MEDIUM').toUpperCase()}] {f?.title} ({f?.cwe})
                    </div>
                  );
                }

                if (evt.event_type === 'finding.validated') {
                  const f = evt.payload.finding;
                  return (
                    <div key={evt.event_id} className="text-rose-200 font-bold bg-rose-950/40 p-2.5 rounded-xl border border-rose-700/60 shadow-inner">
                      <span className="text-slate-400">[{time}]</span> ✔ [VERIFIED VULNERABILITY CONFIRMED]: [{(f?.severity || 'HIGH').toUpperCase()}] {f?.title}
                      <div className="text-[11px] text-slate-300 font-normal mt-0.5 font-mono">
                        &gt; Location: {f?.affected_endpoint || f?.affected_asset}
                      </div>
                    </div>
                  );
                }

                if (evt.event_type === 'defense.verified') {
                  const d = evt.payload.defense;
                  return (
                    <div key={evt.event_id} className="text-emerald-200 font-bold bg-emerald-950/40 p-2 rounded-xl border border-emerald-700/60 shadow-inner">
                      <span className="text-slate-400">[{time}]</span> 🛡️ [DEFENSE VERIFIED &amp; MITIGATED]: [{(d?.status || 'PASSED').toUpperCase()}] {d?.title}
                      <div className="text-[11px] text-emerald-300/80 font-normal mt-0.5 font-mono">
                        &gt; {d?.evidence_summary}
                      </div>
                    </div>
                  );
                }

                if (evt.event_type === 'agent.completed') {
                  return (
                    <div key={evt.event_id} className="text-emerald-400/90 py-0.5">
                      <span className="text-slate-500">[{time}]</span> ✔ <span className="font-bold">[{evt.payload.role}]</span> {evt.payload.summary}
                    </div>
                  );
                }

                return (
                  <div key={evt.event_id} className="text-slate-300 py-0.5">
                    <span className="text-slate-500">[{time}]</span> [{evt.event_type}] {JSON.stringify(evt.payload)}
                  </div>
                );
              })}
              <div ref={terminalEndRef} />
            </div>

          </div>
        </div>

      </div>

    </div>
  );
};
export default LiveAssessmentView;
