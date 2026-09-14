import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { LiveAssessmentView } from './components/LiveAssessmentView';
import { FindingsView } from './components/FindingsView';
import { AttackSurfaceView } from './components/AttackSurfaceView';
import { ReportView } from './components/ReportView';
import { HistoryComparisonView } from './components/HistoryComparisonView';
import { ScopeGuardianView } from './components/ScopeGuardianView';
import { ToolsSandboxView } from './components/ToolsSandboxView';
import { LaunchScanModal } from './components/LaunchScanModal';
import { TestSuiteModal } from './components/TestSuiteModal';
import { ScanState, ScanEvent, ScanMode, ScanDepth, ScopeConfig, AgentInfo, RepoMetadata, SourceFile } from './types';
import { pentestEngine } from './lib/pentestEngine';

export function App() {
  // Support clean URL routing between Landing Page ("/") and Main App ("?view=app" or "#/app")
  const [currentView, setCurrentView] = useState<'landing' | 'app'>(() => {
    if (typeof window !== 'undefined') {
      const search = window.location.search;
      const hash = window.location.hash;
      const pathname = window.location.pathname;
      if (search.includes('view=app') || hash.includes('/app') || pathname.startsWith('/app')) {
        return 'app';
      }
    }
    return 'landing';
  });

  const [activeTab, setActiveTab] = useState<string>('assessment');
  const [isLaunchModalOpen, setIsLaunchModalOpen] = useState(false);
  const [isTestSuiteOpen, setIsTestSuiteOpen] = useState(false);
  const [scanState, setScanState] = useState<ScanState | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Sync browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      const search = window.location.search;
      const hash = window.location.hash;
      const pathname = window.location.pathname;
      if (search.includes('view=app') || hash.includes('/app') || pathname.startsWith('/app')) {
        setCurrentView('app');
      } else {
        setCurrentView('landing');
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleGetStarted = () => {
    setCurrentView('app');
    if (typeof window !== 'undefined') {
      window.history.pushState({}, '', '?view=app');
    }
  };

  const handleBackToLanding = () => {
    setCurrentView('landing');
    if (typeof window !== 'undefined') {
      window.history.pushState({}, '', '/');
    }
  };

  const [scopeConfig, setScopeConfig] = useState<ScopeConfig>({
    allowed_domains: ['localhost', '127.0.0.1', 'demo-target', 'github.com'],
    allowed_urls: ['http://localhost:8080'],
    allowed_ports: [80, 443, 3000, 5000, 8080],
    allowed_local_paths: ['./demo-target', './'],
    excluded_paths: ['/logout', '/delete-account', '/admin/reset-db', 'node_modules'],
    max_requests_per_minute: 120,
    allow_destructive_payloads: false
  });

  useEffect(() => {
    const unsubscribe = pentestEngine.onEvent((event: ScanEvent) => {
      setScanState(prev => {
        if (!prev) return prev;

        const updatedEvents = [...prev.events, event];
        const updatedAgents: Record<string, AgentInfo> = { ...prev.agents };
        const updatedEndpoints = [...prev.endpoints];
        const updatedTechnologies = [...prev.technologies];
        const updatedFindings = [...prev.findings];

        // Handle agent lifecycle
        if (event.event_type === 'agent.created' || event.event_type === 'agent.started') {
          const agentId = event.payload.agent_id;
          if (agentId) {
            const p = event.payload;
            updatedAgents[agentId] = {
              agent_id: agentId,
              parent_agent_id: p.parent_agent_id || null,
              role: p.role || 'Agent',
              objective: p.objective || '',
              status: p.status || 'running',
              current_task: p.current_task || p.objective || 'Executing tasks',
              iterations: (updatedAgents[agentId]?.iterations || 0) + 1,
              tool_calls_count: updatedAgents[agentId]?.tool_calls_count || 0
            };
          }
        }

        if (event.event_type === 'agent.completed') {
          const agentId = event.payload.agent_id;
          if (agentId && updatedAgents[agentId]) {
            updatedAgents[agentId].status = 'completed';
            updatedAgents[agentId].current_task = event.payload.summary || 'Task completed';
          }
        }

        if (event.event_type === 'tool.completed') {
          const agentId = event.payload.agent_id;
          if (agentId && updatedAgents[agentId]) {
            updatedAgents[agentId].tool_calls_count += 1;
          }
        }

        // Handle asset discoveries
        if (event.event_type === 'asset.discovered' && event.payload.asset_type === 'technology') {
          if (!updatedTechnologies.includes(event.payload.value)) {
            updatedTechnologies.push(event.payload.value);
          }
        }

        // Handle endpoint discoveries
        if (event.event_type === 'endpoint.discovered') {
          const url = event.payload.url;
          if (!updatedEndpoints.some(e => e.url === url)) {
            updatedEndpoints.push({
              url,
              path: event.payload.path || url.replace(/^https?:\/\/[^/]+/, '') || '/',
              method: event.payload.method || 'GET',
              parameters: event.payload.parameters || [],
              auth_required: false,
              source_agent: event.payload.source_agent || 'ReconAgent',
              status_code: 200
            });
          }
        }

        // Handle finding lifecycle
        if (event.event_type === 'finding.created') {
          const f = event.payload.finding;
          if (f && !updatedFindings.some(existing => existing.id === f.id)) {
            updatedFindings.push(f);
          }
        }

        if (event.event_type === 'finding.validated') {
          const validated = event.payload.finding;
          const idx = updatedFindings.findIndex(f => f.id === validated.id);
          if (idx !== -1) {
            updatedFindings[idx] = validated;
          } else {
            updatedFindings.push(validated);
          }
        }

        // Handle architectural lifecycle events
        let updatedProfile = prev.application_profile;
        let updatedSurface = prev.attack_surface;
        let updatedPlan = prev.test_plan;
        const updatedObservations = [...(prev.observations || [])];
        const updatedHypotheses = [...(prev.hypotheses || [])];
        let projectId = prev.project_id;
        let versionId = prev.version_id;
        let projectHash = prev.project_hash;

        if (event.event_type === 'project.fingerprinted') {
          projectId = event.payload.project_id;
          versionId = event.payload.version_id;
          projectHash = event.payload.project_hash;
        }

        if (event.event_type === 'recon.profile_generated') {
          updatedProfile = event.payload.profile;
        }

        if (event.event_type === 'surface.mapped') {
          updatedSurface = event.payload.attack_surface;
        }

        if (event.event_type === 'test_plan.created') {
          updatedPlan = event.payload.test_plan;
        }

        if (event.event_type === 'observation.recorded') {
          const obs = event.payload.observation;
          if (obs && !updatedObservations.some(o => o.id === obs.id)) {
            updatedObservations.push(obs);
          }
        }

        if (event.event_type === 'hypothesis.generated') {
          const hyp = event.payload.hypothesis;
          if (hyp && !updatedHypotheses.some(h => h.id === hyp.id)) {
            updatedHypotheses.push(hyp);
          }
        }

        // Handle verified defenses
        const updatedDefenses = [...(prev.verified_defenses || [])];
        if (event.event_type === 'defense.verified') {
          const d = event.payload.defense;
          if (d && !updatedDefenses.some(existing => existing.id === d.id)) {
            updatedDefenses.push(d);
          }
        }

        if (event.event_type === 'scan.completed') {
          setIsScanning(false);
          // Mark all agents completed to ensure none remain stuck in running
          Object.keys(updatedAgents).forEach(aid => {
            if (updatedAgents[aid].status === 'running') {
              updatedAgents[aid].status = 'completed';
              updatedAgents[aid].current_task = 'Task completed';
            }
          });
        }

        return {
          ...prev,
          project_id: projectId,
          version_id: versionId,
          project_hash: projectHash,
          application_profile: updatedProfile,
          attack_surface: updatedSurface,
          test_plan: updatedPlan,
          observations: updatedObservations,
          hypotheses: updatedHypotheses,
          events: updatedEvents,
          agents: updatedAgents,
          endpoints: updatedEndpoints,
          technologies: updatedTechnologies,
          findings: updatedFindings,
          verified_defenses: updatedDefenses,
          posture_status: event.payload?.posture_status || prev.posture_status || (updatedFindings.length > 0 ? 'vulnerabilities_found' : 'hardened_resilient'),
          status: event.event_type === 'scan.completed' ? 'completed' : prev.status
        };
      });
    });

    return () => unsubscribe();
  }, []);

  const handleLaunchScan = async (
    target: string,
    mode: ScanMode,
    depth: ScanDepth,
    instruction: string,
    scope: ScopeConfig,
    options?: {
      targetType?: 'url' | 'github_repo' | 'uploaded_code';
      repoMetadata?: RepoMetadata;
      sourceFiles?: SourceFile[];
    }
  ) => {
    setScopeConfig(scope);
    const scanId = Math.random().toString(36).substring(2, 11);

    const initialState: ScanState = {
      scan_id: scanId,
      target,
      mode,
      depth,
      target_type: options?.targetType || (target.includes('github.com') ? 'github_repo' : 'url'),
      repo_metadata: options?.repoMetadata,
      source_files: options?.sourceFiles,
      status: 'running',
      progress: 0,
      technologies: [],
      endpoints: [],
      findings: [],
      agents: {},
      events: [],
      started_at: new Date().toISOString()
    };

    setScanState(initialState);
    setIsScanning(true);
    setActiveTab('assessment');

    // Run autonomous assessment
    const result = await pentestEngine.runAutonomousAssessment(scanId, target, mode, depth, instruction, scope, options);

    // Synchronize canonical single-source-of-truth scan state
    if (result) {
      setScanState(prev => {
        if (!prev || prev.scan_id !== scanId) return prev;
        return {
          ...prev,
          status: 'completed',
          project_id: result.projectId || prev.project_id || 'proj-shop-app',
          version_id: result.versionId || prev.version_id || 'v1',
          findings: result.findings,
          endpoints: result.endpoints,
          technologies: result.technologies,
          verified_defenses: result.verifiedDefenses,
          posture_status: result.postureStatus,
          application_profile: result.profile,
          attack_surface: result.attackSurface,
          test_plan: result.testPlan,
          observations: result.observations,
          hypotheses: result.hypotheses,
          project_hash: result.projectHash,
        };
      });

      // Synchronize to backend history store
      try {
        fetch('/api/projects/record', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: scanId,
            project_id: result.projectId || 'proj-shop-app',
            version_id: result.versionId || 'v1',
            project_hash: result.projectHash,
            findings: result.findings,
            verified_defenses: result.verifiedDefenses,
            overall_risk_score: result.findings.filter(f => (f.status || 'CONFIRMED') === 'CONFIRMED').length > 0 ? 8.5 : 0.0,
          }),
        }).catch(err => console.warn('History sync notification:', err));
      } catch (err) {
        console.warn('History sync error:', err);
      }
    }
  };

  const validatedFindingsCount = scanState
    ? scanState.findings.filter(f => (f.status || (f.validation_status === 'validated' ? 'CONFIRMED' : 'POTENTIAL')) === 'CONFIRMED').length
    : 0;

  if (currentView === 'landing') {
    return <LandingPage onGetStarted={handleGetStarted} />;
  }

  return (
    <div className="min-h-screen bg-[#051014] text-slate-100 font-sans selection:bg-teal-600 selection:text-white flex flex-col w-full max-w-full">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isScanning={isScanning}
        onOpenLaunchModal={() => setIsLaunchModalOpen(true)}
        onOpenTestSuite={() => setIsTestSuiteOpen(true)}
        findingsCount={validatedFindingsCount}
        onBackToLanding={handleBackToLanding}
      />

      {/* Main Content Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 min-w-0">
        {activeTab === 'assessment' && (
          <LiveAssessmentView
            scanState={scanState}
            onOpenLaunchModal={() => setIsLaunchModalOpen(true)}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsView
            findings={scanState?.findings || []}
            scanState={scanState}
          />
        )}

        {activeTab === 'surface' && (
          <AttackSurfaceView
            scanState={scanState}
          />
        )}

        {activeTab === 'reports' && (
          <ReportView
            scanState={scanState}
          />
        )}

        {activeTab === 'history' && (
          <HistoryComparisonView
            scanState={scanState}
          />
        )}

        {activeTab === 'scope' && (
          <ScopeGuardianView
            scopeConfig={scopeConfig}
          />
        )}

        {activeTab === 'tools' && (
          <ToolsSandboxView />
        )}
      </main>

      {/* Launch Pentest Modal */}
      <LaunchScanModal
        isOpen={isLaunchModalOpen}
        onClose={() => setIsLaunchModalOpen(false)}
        onLaunch={handleLaunchScan}
      />

      {/* 10-Point Architectural Test Suite Modal */}
      <TestSuiteModal
        isOpen={isTestSuiteOpen}
        onClose={() => setIsTestSuiteOpen(false)}
      />

      {/* Subtle Footer */}
      <footer className="border-t border-[#113137] bg-[#07171a] py-4 text-center text-xs text-teal-200/80 font-mono">
        Red Team
      </footer>
    </div>
  );
}

export default App;
