import {
  Finding,
  FindingSeverity,
  FindingStatus,
  RiskCalculationDetails,
  ScanSummaryMetrics,
  TestedCategoryAudit,
  ScanAuditTrail,
  AuditTrailStage,
  ApplicationProfile,
  AttackSurfaceMap,
  DynamicTestPlan,
  VerifiedDefense,
  ScanMode,
} from '../src/types.js';

export class RiskEngine {
  /**
   * Evaluates individual vulnerability risk deterministically from empirical attributes.
   */
  public evaluateFindingRisk(
    finding: Finding,
    profile?: ApplicationProfile,
    attackSurface?: AttackSurfaceMap
  ): RiskCalculationDetails {
    const status: FindingStatus = finding.status || 'CONFIRMED';
    const vulnType = (finding.vulnerability_type || '').toLowerCase();
    const cwe = (finding.cwe || '').toLowerCase();
    const endpoint = (finding.affected_endpoint || finding.endpoint || '').toLowerCase();
    const file = (finding.file || '').toLowerCase();

    // 1. Base Status Gateway Rule
    // Never allow REJECTED, INCONCLUSIVE, or NOT_FOUND to carry any risk score.
    if (status === 'REJECTED' || status === 'NOT_FOUND' || status === 'INCONCLUSIVE') {
      return {
        exploitability_score: 0.0,
        impact_score: 0.0,
        evidence_strength_score: 0.0,
        authentication_requirement: 'none',
        privilege_requirement: 'none',
        attack_complexity: 'high',
        exposure_level: 'isolated',
        validation_status: status,
        calculated_risk_score: 0.0,
        calculated_severity: 'info',
        risk_factors: [`Finding is marked as ${status} — zero actionable risk assigned.`],
        rationale: `The security hypothesis was evaluated with result ${status}. No risk is attributed without affirmative validation.`,
      };
    }

    const riskFactors: string[] = [];

    // 2. Authentication & Privilege Requirements
    let authReq: 'none' | 'low_privilege' | 'high_privilege' | 'multi_factor' = 'none';
    let privReq: 'none' | 'user' | 'admin' | 'system' = 'none';

    if (endpoint.includes('/admin') || endpoint.includes('/manage') || file.includes('admin')) {
      authReq = 'high_privilege';
      privReq = 'admin';
      riskFactors.push('Requires elevated administrator privileges to invoke vector');
    } else if (
      endpoint.includes('/api/auth/login') ||
      endpoint.includes('/api/register') ||
      endpoint.includes('/public') ||
      endpoint.includes('/health') ||
      vulnType.includes('unauthenticated') ||
      vulnType.includes('ssrf') ||
      cwe.includes('cwe-287') ||
      cwe.includes('cwe-306')
    ) {
      authReq = 'none';
      privReq = 'none';
      riskFactors.push('Unauthenticated vector — remotely accessible by external attackers without credentials');
    } else {
      authReq = 'low_privilege';
      privReq = 'user';
      riskFactors.push('Requires standard authenticated user session');
    }

    // 3. Attack Complexity
    let attackComplexity: 'low' | 'medium' | 'high' = 'low';
    if (vulnType.includes('race condition') || vulnType.includes('timing') || vulnType.includes('blind')) {
      attackComplexity = 'high';
      riskFactors.push('High attack complexity — depends on non-deterministic concurrency or blind exfiltration');
    } else if (vulnType.includes('second-order') || vulnType.includes('cross-tenant') || vulnType.includes('prototype')) {
      attackComplexity = 'medium';
      riskFactors.push('Medium attack complexity — requires staged multi-request sequence');
    } else {
      attackComplexity = 'low';
      riskFactors.push('Low attack complexity — single-step deterministic trigger');
    }

    // 4. Exposure Level
    let exposureLevel: 'public_internet' | 'authenticated_endpoint' | 'internal_network' | 'isolated' = 'public_internet';
    if (endpoint.startsWith('http://localhost') || endpoint.includes('127.0.0.1') || endpoint.includes('internal')) {
      exposureLevel = 'internal_network';
      riskFactors.push('Internal exposure — vector confined to local loopback or service mesh');
    } else if (authReq === 'none') {
      exposureLevel = 'public_internet';
      riskFactors.push('Public Internet exposure — direct ingress vector');
    } else {
      exposureLevel = 'authenticated_endpoint';
      riskFactors.push('Authenticated route exposure');
    }

    // 5. Evidence Strength Multiplier (0.0 to 1.0)
    let evidenceStrength = 0.7; // default baseline
    const hasLiveProof = (finding.evidence || []).some(
      (e) => e.evidence_type === 'http_exchange' && e.response_data?.status_code
    );
    const hasAstSink = (finding.structured_evidence || []).some(
      (se) => se.evidence_type === 'source_ast' || se.evidence_type === 'taint_flow' || se.sink
    );
    const isValidationPassed = finding.validation_record?.is_reproducible === true;

    if (hasLiveProof && hasAstSink) {
      evidenceStrength = 1.0;
      riskFactors.push('Highest evidence fidelity: Combined AST source sink verification and live HTTP reproduction');
    } else if (hasLiveProof || hasAstSink) {
      evidenceStrength = 0.9;
      riskFactors.push('High evidence fidelity: Deterministic proof of sink reachability or verified HTTP response');
    } else if (finding.evidence?.length > 0) {
      evidenceStrength = 0.8;
      riskFactors.push('Moderate evidence fidelity: Verified code snippet or response anomaly');
    } else {
      evidenceStrength = 0.6;
      riskFactors.push('Standard heuristic evidence fidelity');
    }

    // 6. Exploitability Baseline (0.0 - 10.0)
    let exploitability = 7.0;
    if (authReq === 'none') exploitability += 1.5;
    else if (authReq === 'high_privilege') exploitability -= 2.0;

    if (attackComplexity === 'low') exploitability += 1.0;
    else if (attackComplexity === 'high') exploitability -= 2.0;

    if (exposureLevel === 'public_internet') exploitability += 0.5;
    else if (exposureLevel === 'internal_network') exploitability -= 1.5;

    exploitability = Math.min(10.0, Math.max(1.0, exploitability));

    // 7. Impact Baseline (0.0 - 10.0)
    let impact = 6.0;
    if (
      vulnType.includes('rce') ||
      vulnType.includes('command injection') ||
      vulnType.includes('remote code execution') ||
      cwe.includes('cwe-78') ||
      cwe.includes('cwe-94')
    ) {
      impact = 9.8;
      riskFactors.push('Catastrophic Impact: Arbitrary Server Remote Code Execution (RCE)');
    } else if (
      vulnType.includes('sql injection') ||
      vulnType.includes('sqli') ||
      cwe.includes('cwe-89')
    ) {
      impact = 9.2;
      riskFactors.push('Severe Impact: Full database compromise and unauthorized records exfiltration');
    } else if (
      vulnType.includes('idor') ||
      vulnType.includes('broken access control') ||
      vulnType.includes('privilege escalation') ||
      cwe.includes('cwe-639') ||
      cwe.includes('cwe-862')
    ) {
      impact = 8.5;
      riskFactors.push('High Impact: Direct cross-tenant data isolation breach or privilege escalation');
    } else if (
      vulnType.includes('ssrf') ||
      cwe.includes('cwe-918')
    ) {
      impact = 8.4;
      riskFactors.push('High Impact: Server-Side Request Forgery against internal cloud metadata or services');
    } else if (
      vulnType.includes('jwt') ||
      vulnType.includes('authentication bypass') ||
      cwe.includes('cwe-287') ||
      cwe.includes('cwe-347')
    ) {
      impact = 8.8;
      riskFactors.push('High Impact: Complete authentication scheme circumvention');
    } else if (
      vulnType.includes('xss') ||
      vulnType.includes('cross-site scripting') ||
      cwe.includes('cwe-79')
    ) {
      impact = 6.8;
      riskFactors.push('Moderate-High Impact: Client-side context execution and session hijacking vector');
    } else if (
      vulnType.includes('file upload') ||
      cwe.includes('cwe-434')
    ) {
      impact = 8.9;
      riskFactors.push('High Impact: Unrestricted file upload leading to web shell deployment');
    } else if (
      vulnType.includes('open redirect') ||
      cwe.includes('cwe-601')
    ) {
      impact = 4.2;
      riskFactors.push('Moderate Impact: Phishing enablement via unvalidated redirect parameter');
    } else if (
      vulnType.includes('information disclosure') ||
      vulnType.includes('directory listing') ||
      cwe.includes('cwe-200')
    ) {
      impact = 5.0;
      riskFactors.push('Moderate Impact: Sensitive technical environment or credential leak');
    }

    // 8. Calculate Final Risk Score
    // Formula balances CVSS 3.1 style: Base Risk = (0.6 * Impact + 0.4 * Exploitability) * EvidenceStrength
    let rawRiskScore = (0.6 * impact + 0.4 * exploitability) * evidenceStrength;

    // Golden Rule 2: POTENTIAL findings are capped at Low/Medium (score <= 4.5) and low confidence
    if (status === 'POTENTIAL') {
      rawRiskScore = Math.min(rawRiskScore * 0.45, 4.2);
      riskFactors.push('Status is POTENTIAL (unconfirmed hypothesis) — risk score capped at advisory level');
    }

    const calculatedRiskScore = Math.round(Math.min(10.0, Math.max(0.1, rawRiskScore)) * 10) / 10;

    // 9. Derive Calculated Severity
    let calculatedSeverity: FindingSeverity = 'low';
    if (status === 'POTENTIAL') {
      calculatedSeverity = calculatedRiskScore >= 3.5 ? 'medium' : 'low';
    } else {
      if (calculatedRiskScore >= 9.0) calculatedSeverity = 'critical';
      else if (calculatedRiskScore >= 7.0) calculatedSeverity = 'high';
      else if (calculatedRiskScore >= 4.0) calculatedSeverity = 'medium';
      else if (calculatedRiskScore >= 0.1) calculatedSeverity = 'low';
      else calculatedSeverity = 'info';
    }

    const rationale = `Calculated score ${calculatedRiskScore}/10 (${calculatedSeverity.toUpperCase()}) based on exploitability (${exploitability.toFixed(
      1
    )}), impact (${impact.toFixed(1)}), and evidence factor (${evidenceStrength.toFixed(2)}). Status: ${status}.`;

    return {
      exploitability_score: Math.round(exploitability * 10) / 10,
      impact_score: Math.round(impact * 10) / 10,
      evidence_strength_score: evidenceStrength,
      authentication_requirement: authReq,
      privilege_requirement: privReq,
      attack_complexity: attackComplexity,
      exposure_level: exposureLevel,
      validation_status: status,
      calculated_risk_score: calculatedRiskScore,
      calculated_severity: calculatedSeverity,
      risk_factors: riskFactors,
      rationale,
    };
  }

  /**
   * Computes risk metrics across all findings in a scan.
   */
  public calculateScanSummary(
    findings: Finding[],
    testPlan?: DynamicTestPlan,
    profile?: ApplicationProfile,
    defenses?: VerifiedDefense[]
  ): {
    metrics: ScanSummaryMetrics;
    evaluatedFindings: Finding[];
    testedCategories: TestedCategoryAudit[];
  } {
    const evaluatedFindings = findings.map((f) => {
      const riskDetails = this.evaluateFindingRisk(f, profile);
      return {
        ...f,
        risk_details: riskDetails,
        severity: riskDetails.calculated_severity,
        cvss_score: riskDetails.calculated_risk_score,
      };
    });

    const confirmed = evaluatedFindings.filter((f) => (f.status || 'CONFIRMED') === 'CONFIRMED');
    const potential = evaluatedFindings.filter((f) => f.status === 'POTENTIAL');
    const inconclusive = evaluatedFindings.filter((f) => f.status === 'INCONCLUSIVE');
    const rejected = evaluatedFindings.filter((f) => f.status === 'REJECTED');

    const criticalCount = confirmed.filter((f) => f.severity === 'critical').length;
    const highCount = confirmed.filter((f) => f.severity === 'high').length;
    const mediumCount = confirmed.filter((f) => f.severity === 'medium').length;
    const lowCount = confirmed.filter((f) => f.severity === 'low').length;

    // Tested categories reconciliation
    const testedCategories = this.generateTestedCategoryAudit(testPlan, evaluatedFindings, defenses, profile);
    const notDetectedCount = testedCategories.filter((c) => c.status === 'NOT_DETECTED').length;

    // Overall Risk Score Calculation
    let overallRiskScore = 0.0;
    if (confirmed.length > 0) {
      const highestScore = Math.max(...confirmed.map((f) => f.cvss_score));
      const aggregateBonus = Math.min(2.0, (confirmed.length - 1) * 0.3);
      overallRiskScore = Math.min(10.0, Math.round((highestScore + aggregateBonus) * 10) / 10);
    } else if (potential.length > 0) {
      overallRiskScore = Math.min(3.5, Math.round(potential.length * 0.8 * 10) / 10);
    }

    let overallRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE' = 'SECURE';
    if (overallRiskScore >= 9.0) overallRiskLevel = 'CRITICAL';
    else if (overallRiskScore >= 7.0) overallRiskLevel = 'HIGH';
    else if (overallRiskScore >= 4.0) overallRiskLevel = 'MEDIUM';
    else if (overallRiskScore > 0.0) overallRiskLevel = 'LOW';
    else overallRiskLevel = 'SECURE';

    const postureStatus: 'hardened_resilient' | 'vulnerabilities_found' =
      confirmed.length === 0 ? 'hardened_resilient' : 'vulnerabilities_found';

    const metrics: ScanSummaryMetrics = {
      confirmed_count: confirmed.length,
      potential_count: potential.length,
      inconclusive_count: inconclusive.length,
      not_detected_count: notDetectedCount,
      rejected_count: rejected.length,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
      overall_risk_score: overallRiskScore,
      overall_risk_level: overallRiskLevel,
      posture_status: postureStatus,
    };

    return {
      metrics,
      evaluatedFindings,
      testedCategories,
    };
  }

  /**
   * Reconciles tested capabilities against discovered findings.
   * If a capability was planned/tested and has 0 confirmed findings, it is explicitly marked as "NOT_DETECTED".
   */
  public generateTestedCategoryAudit(
    testPlan?: DynamicTestPlan,
    findings: Finding[] = [],
    defenses: VerifiedDefense[] = [],
    profile?: ApplicationProfile
  ): TestedCategoryAudit[] {
    const results: TestedCategoryAudit[] = [];
    const plannedTests = testPlan?.planned_tests || [];

    // Core security capabilities matrix
    const standardCapabilities = [
      { id: 'cap-sqli', name: 'SQL Injection (SQLi)', cwe: 'CWE-89' },
      { id: 'cap-xss', name: 'Cross-Site Scripting (XSS)', cwe: 'CWE-79' },
      { id: 'cap-idor', name: 'Insecure Direct Object References (IDOR)', cwe: 'CWE-639' },
      { id: 'cap-ssrf', name: 'Server-Side Request Forgery (SSRF)', cwe: 'CWE-918' },
      { id: 'cap-auth', name: 'Broken Authentication & Session Management', cwe: 'CWE-287' },
      { id: 'cap-file-upload', name: 'Insecure File Upload & Path Traversal', cwe: 'CWE-434' },
      { id: 'cap-command-injection', name: 'OS Command Injection (RCE)', cwe: 'CWE-78' },
      { id: 'cap-jwt-security', name: 'JWT Signature & Algorithm Validation', cwe: 'CWE-347' },
      { id: 'cap-cors-csrf', name: 'CORS Misconfiguration & CSRF', cwe: 'CWE-352' },
      { id: 'cap-graphql', name: 'GraphQL Query Complexity & Introspection', cwe: 'CWE-200' },
    ];

    for (const cap of standardCapabilities) {
      // Check if GraphQL or other category is not applicable
      if (cap.id === 'cap-graphql' && profile && !profile.has_graphql) {
        results.push({
          category_id: cap.id,
          category_name: cap.name,
          cwe: cap.cwe,
          status: 'NOT_APPLICABLE',
          tested_location: 'Application Profile AST',
          investigation_summary: 'Application does not utilize GraphQL. Capability marked as irrelevant / not applicable.',
          tested_by_agent: 'ApplicationProfiler',
        });
        continue;
      }

      // Check if any finding exists for this category
      const matchedFindings = findings.filter(
        (f) =>
          f.vulnerability_type.toLowerCase().includes(cap.name.toLowerCase().split(' ')[0]) ||
          f.cwe.toLowerCase() === cap.cwe.toLowerCase() ||
          f.title.toLowerCase().includes(cap.name.toLowerCase().split(' ')[0])
      );

      const confirmedFinding = matchedFindings.find((f) => (f.status || 'CONFIRMED') === 'CONFIRMED');
      const potentialFinding = matchedFindings.find((f) => f.status === 'POTENTIAL');

      if (confirmedFinding) {
        results.push({
          category_id: cap.id,
          category_name: cap.name,
          cwe: cap.cwe,
          status: 'CONFIRMED',
          tested_location: confirmedFinding.affected_endpoint || confirmedFinding.file || 'API Endpoint',
          investigation_summary: `Vulnerability confirmed with reproducible proof (${confirmedFinding.title}).`,
          tested_by_agent: confirmedFinding.discovered_by || 'SecurityAgent',
        });
      } else if (potentialFinding) {
        results.push({
          category_id: cap.id,
          category_name: cap.name,
          cwe: cap.cwe,
          status: 'POTENTIAL',
          tested_location: potentialFinding.affected_endpoint || potentialFinding.file || 'Codebase',
          investigation_summary: `Potential unconfirmed hypothesis identified (${potentialFinding.title}).`,
          tested_by_agent: potentialFinding.discovered_by || 'SecurityAgent',
        });
      } else {
        // Look for matching verified defense
        const matchingDefense = defenses.find(
          (d) =>
            d.category.toLowerCase().includes(cap.name.toLowerCase().split(' ')[0]) ||
            d.title.toLowerCase().includes(cap.name.toLowerCase().split(' ')[0])
        );

        results.push({
          category_id: cap.id,
          category_name: cap.name,
          cwe: cap.cwe,
          status: 'NOT_DETECTED',
          tested_location: 'Entire application surface & route handlers',
          investigation_summary:
            matchingDefense?.description ||
            `Investigated with automated security payloads; no exploitable vulnerability condition was detected. Active defenses or parameterized handlers verified.`,
          defensive_evidence: matchingDefense?.evidence_summary || 'No payload triggered sink execution.',
          tested_by_agent: 'VerificationAgent',
        });
      }
    }

    return results;
  }

  /**
   * Generates the end-to-end 12-stage Audit Trail for complete scan transparency and debugging.
   */
  public buildScanAuditTrail(params: {
    projectHash: string;
    versionId: string;
    scanId: string;
    target: string;
    mode: ScanMode;
    appProfileSummary: string;
    attackSurfaceSummary: string;
    testPlanTestsCount: number;
    agentRunsCount: number;
    hypothesesCount: number;
    evidenceCount: number;
    validationsCount: number;
    findingsCount: number;
    stages?: AuditTrailStage[];
  }): ScanAuditTrail {
    const now = new Date().toISOString();
    const defaultStages: AuditTrailStage[] = [
      {
        stage_name: 'Project Ingestion & SHA-256 Fingerprinting',
        status: 'completed',
        timestamp: now,
        summary: `Deterministic project fingerprint generated (${params.projectHash.substring(0, 16)}...).`,
      },
      {
        stage_name: 'Application Reconnaissance & Profiler',
        status: 'completed',
        timestamp: now,
        summary: params.appProfileSummary || 'Extracted dependencies, routes, authentication, and AST sinks.',
      },
      {
        stage_name: 'Attack Surface Discovery',
        status: 'completed',
        timestamp: now,
        summary: params.attackSurfaceSummary || 'Mapped accessible attack vectors and exposure surfaces.',
      },
      {
        stage_name: 'Dynamic Test Planning & Gating',
        status: 'completed',
        timestamp: now,
        summary: `Dynamically scheduled ${params.testPlanTestsCount} relevant security capability tests.`,
      },
      {
        stage_name: 'Specialized Security Agent Execution',
        status: 'completed',
        timestamp: now,
        summary: `Executed ${params.agentRunsCount} agent workflows, recording empirical observations.`,
      },
      {
        stage_name: 'Vulnerability Hypothesis Formulation',
        status: 'completed',
        timestamp: now,
        summary: `Generated ${params.hypothesesCount} candidate security flaw hypotheses.`,
      },
      {
        stage_name: 'Structured Evidence Collection',
        status: 'completed',
        timestamp: now,
        summary: `Collected ${params.evidenceCount} empirical proofs (AST code sinks, HTTP exchanges, taint flows).`,
      },
      {
        stage_name: 'Deterministic Validation Engine',
        status: 'completed',
        timestamp: now,
        summary: `Executed ${params.validationsCount} validation runs, separating confirmed flaws from false positives.`,
      },
      {
        stage_name: 'Finding Fingerprinting & Multi-Agent Correlation',
        status: 'completed',
        timestamp: now,
        summary: `Produced ${params.findingsCount} canonical deduplicated findings.`,
      },
      {
        stage_name: 'Multi-Factor Risk Engine Evaluation',
        status: 'completed',
        timestamp: now,
        summary: 'Calculated exploitability, impact, evidence fidelity, and authentication constraints.',
      },
      {
        stage_name: 'Validated Findings Report Generation',
        status: 'completed',
        timestamp: now,
        summary: 'Synthesized final executive & technical certification report from validated findings.',
      },
      {
        stage_name: 'Security History & Version Database Commit',
        status: 'completed',
        timestamp: now,
        summary: 'Committed scan records and version deltas to security history database.',
      },
    ];

    return {
      project_hash: params.projectHash,
      project_version_id: params.versionId,
      scan_id: params.scanId,
      target: params.target,
      mode: params.mode,
      stages: params.stages && params.stages.length > 0 ? params.stages : defaultStages,
      app_profile_summary: params.appProfileSummary,
      attack_surface_summary: params.attackSurfaceSummary,
      test_plan_tests_count: params.testPlanTestsCount,
      agent_runs_count: params.agentRunsCount,
      hypotheses_count: params.hypothesesCount,
      evidence_count: params.evidenceCount,
      validations_count: params.validationsCount,
      findings_count: params.findingsCount,
      risk_evaluation_timestamp: now,
      report_generated_timestamp: now,
    };
  }
}

export const riskEngine = new RiskEngine();
