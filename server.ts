import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import {
  getComprehensiveAIStatus,
  getGeminiClient,
  generateGeminiContentWithFallback,
  queryOllama,
  extractAndParseJSON,
  checkOllamaReachability,
} from './server/aiProvider.js';
import {
  inspectGitHubRepository,
  parseGitHubUrl,
} from './server/githubService.js';
import { computeProjectHash } from './server/fingerprintService.js';
import { projectStore } from './server/projectStore.js';
import { profileApplication } from './server/applicationProfiler.js';
import { computeFindingHash } from './server/findingFingerprint.js';
import { serverEvidenceCollector } from './server/evidenceCollector.js';
import { serverValidationEngine } from './server/validationEngine.js';
import { serverFindingCorrelator } from './server/findingCorrelator.js';
import { riskEngine } from './server/riskEngine.js';
import { historyService } from './server/historyService.js';
import { reportGenerator } from './server/reportGenerator.js';
import { architectureTestSuite } from './server/testSuite.js';
import { sourceLocationResolver, ProjectSnapshot } from './server/sourceLocationResolver.js';
import { scanSourceFilesForVulnerabilities } from './server/sastScanner.js';
import { buildGreyBoxAssessment } from './server/greyBoxEngine.js';
import { isZipBufferOrName, extractZipArchiveServer } from './server/zipExtractor.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '25mb' }));

// Helper to normalize, sanitize, and strictly verify finding structure and source locations
function sanitizeFindingsResponse(
  parsed: any,
  target: string,
  projectSnapshotOrHash: ProjectSnapshot | string = 'global_project'
) {
  if (!parsed || typeof parsed !== 'object') {
    return { findings: [], verifiedDefenses: [], technologies: [], endpoints: [] };
  }

  const projectSnapshot: ProjectSnapshot =
    typeof projectSnapshotOrHash === 'object' && projectSnapshotOrHash !== null
      ? projectSnapshotOrHash
      : {
          project_sha: typeof projectSnapshotOrHash === 'string' ? projectSnapshotOrHash : 'global_project',
          files: [],
          mode: 'black_box',
        };

  const projectHash = projectSnapshot.project_sha || 'global_project';

  const rawFindings = Array.isArray(parsed.findings)
    ? parsed.findings.map((f: any, idx: number) => {
        const file = f.file || (f.source_locations && f.source_locations[0]?.file) || '';
        const line = f.line || (f.source_locations && f.source_locations[0]?.line_number) || undefined;
        const endpoint = f.endpoint || f.affected_endpoint || target;
        const param = f.parameter || '';
        const vulnType = f.vulnerability_type || 'Code Vulnerability';
        const cwe = f.cwe || 'CWE-200';

        const findingHash = computeFindingHash({
          project_hash: projectHash,
          vulnerability_type: vulnType,
          file,
          endpoint,
          parameter: param,
          cwe,
        });

        const status = f.status || (f.validation_status === 'validated' ? 'CONFIRMED' : 'POTENTIAL');

        const candidateSourceLocs = Array.isArray(f.source_locations)
          ? f.source_locations.map((loc: any) => ({
              file: loc.file || loc.file_path,
              line_number: typeof loc.line_number === 'number' ? loc.line_number : parseInt(loc.line_number, 10) || undefined,
              line_number_start: typeof loc.line_number_start === 'number' ? loc.line_number_start : undefined,
              line_number_end: typeof loc.line_number_end === 'number' ? loc.line_number_end : undefined,
              snippet: loc.snippet || loc.code_snippet || '',
              function_name: loc.function_name,
            }))
          : file
          ? [{ file, line_number: line, snippet: '' }]
          : [];

        const unverifiedFinding = {
          id: f.id || `ai-find-${idx + 1}`,
          scan_id: projectSnapshot.scan_id || '',
          project_id: projectSnapshot.project_id,
          version_id: projectSnapshot.project_version_id,
          finding_hash: findingHash,
          project_hash: projectHash,
          project_sha: projectHash,
          title: f.title || 'Security Flaw Identified',
          vulnerability_type: vulnType,
          cwe,
          owasp_category: f.owasp_category || 'A01:2021-Broken Access Control',
          severity: ['critical', 'high', 'medium', 'low', 'info'].includes(f.severity?.toLowerCase())
            ? f.severity.toLowerCase()
            : 'medium',
          confidence: typeof f.confidence === 'number' ? f.confidence : 0.85,
          cvss_score: typeof f.cvss_score === 'number' ? f.cvss_score : 7.5,
          status,
          affected_asset: f.affected_asset || target,
          affected_endpoint: endpoint,
          file,
          line,
          endpoint,
          parameter: param,
          plain_english_summary: f.plain_english_summary || f.title,
          business_risk_summary: f.business_risk_summary || 'Potential security impact on confidentiality, integrity, or operations.',
          source_locations: candidateSourceLocs,
          code_patch_diff: f.code_patch_diff || undefined,
          description: f.description || '',
          impact: f.impact || '',
          reproduction_steps: Array.isArray(f.reproduction_steps)
            ? f.reproduction_steps
            : ['Inspect vulnerable source line and verify exploit vector.'],
          remediation: f.remediation || 'Apply input validation, boundary checking, and parameterized safe functions.',
          discovered_by: f.discovered_by || 'SASTVulnerabilityAgent',
          validation_status: status === 'CONFIRMED' ? 'validated' : 'potential',
          evidence: Array.isArray(f.evidence) ? f.evidence : [],
          structured_evidence: Array.isArray(f.structured_evidence) ? f.structured_evidence : [],
        };

        // Strictly verify candidate source location against scanned snapshot
        return sourceLocationResolver.resolveFindingSourceLocations(unverifiedFinding as any, projectSnapshot);
      })
    : [];

  let correlatedFindings = serverFindingCorrelator.correlate(rawFindings);

  // If White-Box mode with uploaded files yielded 0 verified findings, run SAST scanner directly
  if (projectSnapshot.mode === 'white_box' && projectSnapshot.files && projectSnapshot.files.length > 0) {
    const verifiedOnly = correlatedFindings.filter((f: any) => f.source_verification_status === 'VERIFIED');
    if (verifiedOnly.length === 0) {
      const sastResult = scanSourceFilesForVulnerabilities(projectSnapshot.files, target, 'deep_technical');
      const resolvedSast = sourceLocationResolver.resolveAllFindings(sastResult.findings, projectSnapshot);
      correlatedFindings = serverFindingCorrelator.correlate(resolvedSast);
    } else {
      correlatedFindings = verifiedOnly;
    }
  }

  const verifiedDefenses = Array.isArray(parsed.verifiedDefenses)
    ? parsed.verifiedDefenses
    : [];
  const technologies = Array.isArray(parsed.technologies) ? parsed.technologies : [];
  const endpoints = Array.isArray(parsed.endpoints) ? parsed.endpoints : [];
  const domainClassification = parsed.domain_classification || 'Source Code & Application Surface';
  const confirmedCount = correlatedFindings.filter(
    (f: any) => (f.status || 'CONFIRMED') === 'CONFIRMED'
  ).length;
  const postureStatus =
    parsed.posture_status === 'hardened_resilient' && correlatedFindings.length === 0
      ? 'hardened_resilient'
      : correlatedFindings.length > 0
      ? 'vulnerabilities_found'
      : 'hardened_resilient';

  return {
    domain_classification: domainClassification,
    posture_status: postureStatus,
    technologies,
    endpoints,
    findings: correlatedFindings,
    verifiedDefenses,
  };
}

// ============================================================================
// API: Project Identity & Version Fingerprinting (SHA-256)
// ============================================================================
app.post('/api/projects/resolve', (req, res) => {
  try {
    const {
      projectName = '',
      targetType = 'uploaded_code',
      targetLocation = '',
      sourceFiles = [],
      mode = 'white_box',
      metadata = {},
    } = req.body;

    const fingerprint = computeProjectHash(sourceFiles, targetLocation, mode);
    const resolved = projectStore.resolveProjectAndVersion({
      projectName: projectName || targetLocation,
      targetType,
      targetLocation: targetLocation || 'local_target',
      projectHash: fingerprint.project_hash,
      sourceFilesCount: fingerprint.normalized_files_count,
      metadata: { ...metadata, total_bytes: fingerprint.total_bytes },
    });

    const profile = profileApplication(sourceFiles, targetLocation, mode);

    res.json({
      success: true,
      project: resolved.project,
      version: resolved.version,
      isNewProject: resolved.isNewProject,
      isNewVersion: resolved.isNewVersion,
      fingerprint,
      profile,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

app.get('/api/projects', (req, res) => {
  try {
    const projects = projectStore.listProjects();
    res.json({ success: true, projects });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

app.get('/api/projects/:id/versions', (req, res) => {
  try {
    const versions = projectStore.getVersionsForProject(req.params.id);
    res.json({ success: true, versions });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

app.post('/api/fingerprint', (req, res) => {
  try {
    const { files = [], target = '', mode = 'black_box' } = req.body;
    const fingerprint = computeProjectHash(files, target, mode);
    res.json({ success: true, fingerprint });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: AI Engine Status & Local/Cloud Provider Diagnostics
// ============================================================================
app.get('/api/ai/status', async (req, res) => {
  try {
    const status = await getComprehensiveAIStatus();
    res.json(status);
  } catch (err: any) {
    res.status(500).json({
      status: 'error',
      active_provider: 'heuristic_engine',
      is_local: true,
      model: 'Fallback Domain Heuristics',
      error: err?.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// ============================================================================
// API: Test Connection to Configured LLM (Ollama or Gemini)
// ============================================================================
app.post('/api/ai/test-connection', async (req, res) => {
  try {
    const status = await getComprehensiveAIStatus();
    const { active_provider } = status;

    if (active_provider === 'ollama') {
      const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
      const check = await checkOllamaReachability(ollamaBaseUrl);
      if (check.reachable) {
        return res.json({
          success: true,
          provider: 'ollama',
          message: `Successfully connected to local Ollama on ${ollamaBaseUrl}. Installed models: ${check.models.join(', ') || 'None found'}`,
          models: check.models,
        });
      } else {
        return res.status(502).json({
          success: false,
          provider: 'ollama',
          message: `Unable to reach Ollama at ${ollamaBaseUrl}. Ensure Ollama is running ('ollama serve' or 'ollama run llama3.2').`,
        });
      }
    }

    if (active_provider === 'gemini') {
      const gemini = getGeminiClient();
      if (!gemini) {
        return res.status(400).json({
          success: false,
          provider: 'gemini',
          message: 'No GEMINI_API_KEY detected in backend environment (.env).',
        });
      }

      const result = await generateGeminiContentWithFallback('Respond with the single word: "READY"', {
        config: { temperature: 0.1 },
      });

      if (result) {
        return res.json({
          success: true,
          provider: 'gemini',
          model: result.model_used,
          message: `Successfully connected to Google Gemini (${result.model_used}). Engine is live and ready.`,
        });
      }

      // If all cloud models are busy/503
      return res.status(200).json({
        success: false,
        provider: 'gemini',
        message: `Google Gemini API temporarily experiencing high traffic. The engine will automatically use deterministic heuristic fallback or local Ollama.`,
      });
    }

    return res.json({
      success: true,
      provider: 'heuristic_engine',
      message: 'Running standalone local domain heuristic matrix. No external API keys needed.',
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: GitHub Repository Inspection & Security Source Tree
// ============================================================================
app.post('/api/github/inspect', async (req, res) => {
  try {
    const { repoUrl, branch, token } = req.body;
    if (!repoUrl) {
      return res.status(400).json({ success: false, error: 'Repository URL or slug is required (e.g. "https://github.com/owner/repo" or "owner/repo").' });
    }

    const inspection = await inspectGitHubRepository(repoUrl, branch, token);
    const files = (inspection.security_files || []).map(f => ({
      name: f.name,
      path: f.path,
      content: f.content,
      language: f.language,
      size: f.size,
      lines: (f.content || '').split('\n').length,
    }));

    return res.json({
      success: true,
      metadata: {
        owner: inspection.owner,
        name: inspection.name,
        full_name: inspection.full_name,
        description: inspection.description,
        stars: inspection.stars,
        forks: inspection.forks,
        branch: inspection.default_branch,
        default_branch: inspection.default_branch,
        language: inspection.language,
        topics: inspection.topics,
        total_files: inspection.total_files_count,
        files: inspection.tree,
      },
      files,
      ...inspection,
    });
  } catch (err: any) {
    console.warn('[GitHub API] Inspection failed:', err.message);
    return res.status(400).json({ success: false, error: err?.message || 'Could not inspect GitHub repository' });
  }
});

// ============================================================================
// API: Intelligent Real-World Target Security Assessment (Web & Source SAST)
// ============================================================================
app.post('/api/ai/assess-target', async (req, res) => {
  try {
    const { target, mode = 'black_box', depth = 'deep_technical', instruction = '', files = [], repoUrl = '' } = req.body;
    if (!target && !repoUrl) {
      return res.status(400).json({ error: 'Target URL, repository, or source files required' });
    }

    const effectiveTarget = target || repoUrl;

    let effectiveFiles: any[] = Array.isArray(files) ? files : [];
    for (const f of Array.isArray(files) ? files : []) {
      if (f && (f.name?.toLowerCase().endsWith('.zip') || f.path?.toLowerCase().endsWith('.zip') || isZipBufferOrName(f.name || f.path || '', f.content))) {
        try {
          const archiveResult = await extractZipArchiveServer(f.content, f.name || f.path || 'archive.zip');
          effectiveFiles = effectiveFiles.filter(item => item !== f).concat(archiveResult.files);
        } catch (e) {
          console.warn('[Server] Failed to unpack zip in assess-target:', e);
        }
      }
    }

    const isSourceScan = mode === 'white_box' || Boolean(repoUrl) || (Array.isArray(effectiveFiles) && effectiveFiles.length > 0) || effectiveTarget.includes('github.com') || parseGitHubUrl(effectiveTarget) !== null;

    let sourceContextText = '';
    if (isSourceScan && Array.isArray(effectiveFiles) && effectiveFiles.length > 0) {
      sourceContextText = `\n\nACTUAL REPOSITORY SOURCE FILES FOR DEEP SAST AUDIT:\n` +
        effectiveFiles.map((f: any, i: number) => `--- File [${i + 1}/${effectiveFiles.length}]: ${f.path || f.name} (${f.language || 'Code'}) ---\n${f.content || '// Content unavailable'}`).join('\n\n');
    }

    const aiStatus = await getComprehensiveAIStatus();
    const isGreyBox = mode === 'grey_box' || mode === 'gray_box';
    const hostDomain = effectiveTarget.replace(/^https?:\/\//, '').split('/')[0] || 'target.example.com';

    const systemInstruction = isSourceScan
      ? `You are a Principal Cyber Security Architect, Static Code Analysis (SAST) Auditor, and Autonomous Red Team Leader.
Analyze the target Codebase / Repository: "${effectiveTarget}".
Assessment Mode: "white_box" (Deep Source Code SAST Vulnerability Audit)
Depth: "${depth}" (quick_surface or deep_technical)
User Instruction / Context: "${instruction}"
${sourceContextText}

DEEP SAST CODE AUDIT MANDATE:
1. Conduct an inside-out static analysis strictly grounded on the ACTUAL source files provided in the prompt.
2. If files are Python (.py), find vulnerabilities ONLY in those .py files. If Go (.go), only .go files. If TypeScript/JavaScript, only those files.
3. NEVER invent or hallucinate non-existent filenames or routes (e.g. do NOT output "src/routes/users.ts" if no such file exists).
4. Examine:
   - SQL / NoSQL Injection sinks (unparameterized queries, raw string concatenation)
   - Broken Object Level Authorization (BOLA/IDOR) and missing permission checks on routes/handlers
   - Hardcoded secrets, API keys, tokens, or JWT signing secrets (CWE-798)
   - Remote Code Execution (RCE), unsafe eval, child_process.exec, deserialization (CWE-78, CWE-502)
   - Server-Side Request Forgery (SSRF) and unvalidated outbound HTTP calls (CWE-918)
   - Path Traversal and arbitrary file read/write (CWE-22)
   - Broken Authentication, insecure password hashing, session fixation
   - Cross-Site Scripting (XSS), Prototype Pollution (CWE-1321), and insecure CORS
5. FOR EACH IDENTIFIED VULNERABILITY:
   - Provide the EXACT filename and line number from the actual provided files in "source_locations".
   - Provide a complete code remediation diff in "code_patch_diff".
   - Assign the exact CWE and OWASP category.

Output strictly valid JSON conforming to this schema:
{
  "domain_classification": "e.g. Application Codebase",
  "posture_status": "vulnerabilities_found",
  "technologies": ["Discovered Language/Framework 1", "Discovered Language/Framework 2"],
  "endpoints": [{"url": "${effectiveTarget}/app_entry_file", "method": "FILE", "parameters": [], "auth_required": false, "status_code": 200}],
  "findings": [{
    "id": "find-1",
    "title": "Title of Flaw",
    "vulnerability_type": "Vulnerability Type",
    "cwe": "CWE-89",
    "owasp_category": "A03:2021-Injection",
    "severity": "critical",
    "confidence": 0.98,
    "cvss_score": 9.8,
    "affected_asset": "${effectiveTarget}",
    "affected_endpoint": "actual_file_path:line",
    "plain_english_summary": "Plain English summary here",
    "business_risk_summary": "Business impact here",
    "source_locations": [{
      "file": "actual_file_path",
      "line_number": 42,
      "snippet": "actual code snippet from file"
    }],
    "code_patch_diff": "--- a/actual_file\\n+++ b/actual_file\\n@@ -42,1 +42,1 @@\\n- vulnerable_line\\n+ fixed_line",
    "description": "Technical root cause explanation",
    "impact": "Exploit impact description",
    "reproduction_steps": ["Step 1", "Step 2"],
    "remediation": "Remediation guidance.",
    "discovered_by": "SourceASTAnalyzer",
    "evidence": [{
      "id": "ev-1",
      "evidence_type": "code_snippet",
      "description": "Vulnerable Sink in actual file",
      "request_data": { "url": "actual_file_path", "method": "FILE" },
      "response_data": { "status_code": 200, "body_preview": "Snippet preview" }
    }]
  }],
  "verifiedDefenses": []
}`
      : isGreyBox
      ? `You are a Senior Web API Penetration Tester and Grey-Box Application Security Specialist.
Analyze the target API surface: "${effectiveTarget}".
Assessment Mode: "grey_box" (Authenticated API & Business Logic Penetration Testing)
Depth: "${depth}" (quick_surface or deep_technical)
User Instruction / Context: "${instruction}"

GREY BOX API & LOGIC MANDATE:
- Perform authenticated API penetration testing without source code visibility.
- Discover authentic API flaws: Broken Object Level Authorization (BOLA/IDOR, CWE-639), Broken Function Level Authorization (BFLA, CWE-285), Mass Assignment (CWE-915), Webhook SSRF (CWE-918), Rate Limit Bypass, and JWT Token Tampering.
- NEVER output source code files (.ts, .py, .go) or code diffs (this is grey-box API testing).
- Each finding MUST include HTTP exchange evidence (method, URL, headers, and simulated response).

Output strictly valid JSON:
{
  "domain_classification": "e.g. Authenticated REST API & Microservice Gateway",
  "posture_status": "vulnerabilities_found",
  "technologies": ["REST API Gateway", "OAuth2/JWT Auth", "PostgreSQL/Microservices"],
  "endpoints": [
    {"url": "${effectiveTarget}/api/v1/users/me", "method": "GET", "parameters": ["Authorization"], "auth_required": true, "status_code": 200},
    {"url": "${effectiveTarget}/api/v1/invoices/1042", "method": "GET", "parameters": ["invoice_id"], "auth_required": true, "status_code": 200}
  ],
  "findings": [{
    "id": "gb-1",
    "title": "BOLA / IDOR in Resource Handler",
    "vulnerability_type": "Broken Object Level Authorization (BOLA/IDOR)",
    "cwe": "CWE-639",
    "owasp_category": "A01:2021-Broken Access Control",
    "severity": "high",
    "confidence": 0.95,
    "cvss_score": 8.6,
    "affected_asset": "${effectiveTarget}",
    "affected_endpoint": "${effectiveTarget}/api/v1/invoices/{id}",
    "plain_english_summary": "API endpoints allow authenticated users to access resources of other organizations by manipulating URL identifiers.",
    "business_risk_summary": "Cross-tenant data exposure and privacy compliance breach.",
    "description": "Tenant authorization check is not enforced on the resource ID.",
    "impact": "Unauthorized access to private financial data.",
    "reproduction_steps": ["Authenticate as User A (Org 1)", "Request GET /api/v1/invoices/1042 (Org 2)", "Observe HTTP 200 with Org 2 data"],
    "remediation": "Validate object ownership against session token org_id before returning records.",
    "discovered_by": "GreyBoxAPIScanner",
    "evidence": [{
      "id": "ev-gb-1",
      "evidence_type": "http_exchange",
      "description": "Unauthorized access across tenant boundaries",
      "request_data": { "url": "${effectiveTarget}/api/v1/invoices/1042", "method": "GET" },
      "response_data": { "status_code": 200, "body_preview": "{\\"id\\": 1042, \\"org_id\\": \\"other-tenant\\", \\"amount\\": 4500.00}" }
    }]
  }],
  "verifiedDefenses": []
}`
      : `You are a Principal Cyber Security Architect and Autonomous Red Team Leader.
Analyze the target URL/domain: "${effectiveTarget}".
Assessment Mode: "${mode}" (black_box, white_box, or grey_box)
Depth: "${depth}" (quick_surface or deep_technical)
User Instruction / Context: "${instruction}"

BLACK-BOX PENETRATION TESTING & EVIDENCE PRECISION MANDATE:
- For Black Box assessment, test the external network/HTTP perimeter and API attack surface without source code visibility.
- Discover authentic, pointed logical and perimeter security risks that apply to this target (e.g. Missing HSTS/CSP/CORS headers, Reflected XSS, BOLA/IDOR on public API endpoints, Authentication Rate Limit Bypasses, Sensitive Endpoint Exposure, Host Header Injection, or SQL injection over HTTP query params).
- EVIDENCE MUST BE POINTED, CONCRETE, AND APPEAL TO DEVELOPERS:
  * Each finding MUST include complete HTTP exchange evidence with 'request_data' (method, exact URL, request headers, body payload) and 'response_data' (exact status_code e.g. 200/401/500, response headers, body_preview).
  * Explicitly include 'confirmation_proof' explaining WHY this evidence definitively proves the risk is confirmed without false positives.
- REPRODUCTION STEPS MUST SHOW THE AGENT DETECTION TRAJECTORY (4 Clear Steps):
  * Step 1: Baseline Request & Endpoint Fingerprint
  * Step 2: Targeted Payload Injection / Probe
  * Step 3: Server Anomaly & Vulnerability Reflection / Extraction
  * Step 4: Deterministic Confirmation & Non-Destructive PoC Validation
- REMEDIATION MUST INCLUDE CLEAN, ACTIONABLE CODE & SERVER CONFIGURATION PATCHES:
  * Provide clean, copy-pasteable patches in 'remediation_patch' and multi-stack configs in 'remediation_configs' (e.g. Nginx, Node.js/Express, Python FastAPI/Django, Apache).
  * Provide 'remediation_steps' with 3 simple, non-vague actionable steps for engineering teams.

Output strictly valid JSON conforming to this schema:
{
  "domain_classification": "e.g. Global Financial Clearing & Settlement API",
  "posture_status": "vulnerabilities_found",
  "technologies": ["Technology 1", "Technology 2"],
  "endpoints": [{"url": "${effectiveTarget}/api/v1/resource", "method": "GET", "parameters": ["id"], "auth_required": true, "status_code": 200}],
  "findings": [{
    "id": "find-1",
    "title": "Clear Title of Vulnerability",
    "vulnerability_type": "Vulnerability Classification (e.g. Broken Object Level Authorization)",
    "cwe": "CWE-639",
    "owasp_category": "A01:2021-Broken Access Control",
    "severity": "high",
    "confidence": 0.98,
    "cvss_score": 8.5,
    "affected_asset": "${effectiveTarget}",
    "affected_endpoint": "${effectiveTarget}/api/v1/resource",
    "plain_english_summary": "Plain English summary explaining what happened and why it matters in simple terms.",
    "business_risk_summary": "Direct business impact, customer risk, and compliance implications.",
    "description": "Technical root cause explaining the protocol or logic flaw.",
    "impact": "Concrete system impact if exploited.",
    "reproduction_steps": [
      "1. Baseline: Agent sends initial GET request to /api/v1/resource and records baseline status 200.",
      "2. Probe: Agent injects payload parameter ?id=victim_account_id without modifying session token.",
      "3. Anomaly: Server returns victim account profile with HTTP 200 OK without verifying tenant ownership.",
      "4. Confirmation: Secondary non-destructive verification probe confirms deterministic cross-tenant data leak."
    ],
    "remediation": "Clear plain-English explanation of how to fix the issue.",
    "remediation_patch": "server {\\n  listen 443 ssl;\\n  add_header Strict-Transport-Security \\"max-age=31536000; includeSubDomains\\" always;\\n}",
    "remediation_steps": [
      "1. Add the provided configuration or middleware to your reverse proxy/server.",
      "2. Validate authorization policies on all record lookups using session user ID.",
      "3. Test endpoint with curl or security suite to verify 403 Forbidden on cross-tenant requests."
    ],
    "remediation_configs": {
      "Nginx (nginx.conf)": "add_header Strict-Transport-Security \\"max-age=31536000; includeSubDomains\\" always;\\nadd_header Content-Security-Policy \\"default-src 'self';\\" always;",
      "Node.js / Express": "app.use(helmet());\\napp.use(cors({ origin: 'https://yourdomain.com', credentials: true }));",
      "Python (FastAPI / Django)": "from fastapi.middleware.cors import CORSMiddleware\\napp.add_middleware(CORSMiddleware, allow_origins=['https://yourdomain.com'])",
      "Apache (.htaccess)": "Header always set Strict-Transport-Security \\"max-age=31536000; includeSubDomains\\""
    },
    "discovered_by": "BlackBoxPerimeterAgent",
    "evidence": [{
      "id": "ev-1",
      "evidence_type": "http_exchange",
      "description": "Cross-tenant record leaked via unvalidated ID parameter",
      "confirmation_proof": "Confirmed: Server responded with HTTP 200 containing victim_user record when requested with unprivileged attacker_user authorization header.",
      "request_data": {
        "url": "${effectiveTarget}/api/v1/resource?id=102",
        "method": "GET",
        "headers": {
          "Host": "${hostDomain}",
          "Authorization": "Bearer attacker_token_9918",
          "Accept": "application/json"
        }
      },
      "response_data": {
        "status_code": 200,
        "headers": {
          "Content-Type": "application/json",
          "Server": "nginx/1.24"
        },
        "body_preview": "{\\"id\\": 102, \\"owner_email\\": \\"victim@target.com\\", \\"balance\\": 14500.00, \\"tenant_id\\": \\"org_victim_2\\"}"
      }
    }]
  }],
  "verifiedDefenses": [{
    "id": "def-1",
    "category": "Edge & Perimeter Shielding",
    "title": "WAF Rate Limiting Active",
    "status": "passed",
    "description": "Rate limiting verified",
    "tested_vector": "Burst probing",
    "evidence_summary": "HTTP 429 returned on rapid probes"
  }]
}`;

    const targetMode = (isSourceScan ? 'white_box' : mode) as any;
    const projectFingerprint = computeProjectHash(effectiveFiles, effectiveTarget, targetMode);
    const projectSnapshot: ProjectSnapshot = {
      project_id: req.body.projectId || effectiveTarget,
      project_version_id: req.body.versionId || 'v1',
      scan_id: req.body.scanId || `scan-${Date.now()}`,
      project_sha: projectFingerprint.project_hash,
      files: effectiveFiles,
      repoMetadata: req.body.repoMetadata,
      mode: targetMode,
    };

    // --- Provider 1: Local Ollama ---
    if (aiStatus.active_provider === 'ollama') {
      try {
        const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';
        const rawText = await queryOllama(systemInstruction, undefined, ollamaModel);
        const parsed = extractAndParseJSON(rawText);
        if (parsed) {
          const sanitized = sanitizeFindingsResponse(parsed, effectiveTarget, projectSnapshot);
          return res.json({
            success: true,
            source: 'ollama_local',
            model_used: `Ollama (${ollamaModel})`,
            data: sanitized,
          });
        }
      } catch (ollamaErr: any) {
        console.warn('[AI Engine] Ollama generation failed, checking fallback:', ollamaErr?.message);
      }
    }

    // --- Provider 2: Google Gemini Cloud ---
    const geminiResult = await generateGeminiContentWithFallback(systemInstruction, {
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
        maxOutputTokens: 8192,
      },
    });

    if (geminiResult?.text) {
      const parsed = extractAndParseJSON(geminiResult.text);
      if (parsed) {
        const sanitized = sanitizeFindingsResponse(parsed, effectiveTarget, projectSnapshot);
        return res.json({
          success: true,
          source: 'gemini_ai',
          model_used: geminiResult.model_used,
          data: sanitized,
        });
      }
    }

    // --- Deterministic Domain Heuristics Fallback ---
    return res.json({
      success: false,
      source: 'heuristic_fallback',
      message: 'Running intelligent domain-aware Red Team heuristic engine',
    });
  } catch (err: any) {
    console.error('Error in /api/ai/assess-target:', err);
    res.status(500).json({ error: 'Internal assessment error', details: err?.message });
  }
});

// ============================================================================
// API: AI Remediation Code Patch Generator (Local Ollama + Gemini + Templates)
// ============================================================================
app.post('/api/ai/generate-patch', async (req, res) => {
  try {
    const { finding_title, vulnerability_type, cwe, affected_endpoint, remediation } = req.body;
    const aiStatus = await getComprehensiveAIStatus();

    const patchPrompt = `You are a Senior Application Security Engineer.
Generate an actionable code fix patch and configuration guidelines for the following vulnerability:
Vulnerability: ${finding_title} (${vulnerability_type}, ${cwe})
Affected Endpoint: ${affected_endpoint}
Current Guidance: ${remediation}

Provide:
1. Vulnerable code snippet pattern
2. Secure remediated code snippet
3. Unit test / integration test validation snippet
4. Plain-English explanation for developers

Output strictly JSON:
{
  "summary": "Brief summary",
  "vulnerable_code": "code string",
  "secure_code": "code string",
  "unit_test_code": "test string",
  "security_best_practices": ["point 1", "point 2"]
}`;

    // Try Ollama if active
    if (aiStatus.active_provider === 'ollama') {
      try {
        const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';
        const rawText = await queryOllama(patchPrompt, undefined, ollamaModel);
        const parsed = extractAndParseJSON(rawText);
        if (parsed?.secure_code) {
          return res.json({
            success: true,
            source: 'ollama_local',
            model_used: `Ollama (${ollamaModel})`,
            data: parsed,
          });
        }
      } catch (err: any) {
        console.warn('[AI Engine] Ollama patch generation failed:', err?.message);
      }
    }

    // Try Gemini if available
    const patchResult = await generateGeminiContentWithFallback(patchPrompt, {
      config: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    });

    if (patchResult?.text) {
      const parsed = extractAndParseJSON(patchResult.text);
      if (parsed?.secure_code) {
        return res.json({
          success: true,
          model_used: patchResult.model_used,
          data: parsed,
        });
      }
    }

    // Fallback deterministic security patch
    return res.json({
      success: true,
      source: 'deterministic_patch',
      data: {
        summary: `Standard security remediation pattern for ${vulnerability_type || 'vulnerability'}.`,
        vulnerable_code: `// Vulnerable pattern on ${affected_endpoint || '/api/resource'}\napp.get('${affected_endpoint || '/api/resource'}', (req, res) => {\n  // Missing authorization or validation\n  return res.json(resource);\n});`,
        secure_code: `// Secure pattern with authorization enforcement\napp.get('${affected_endpoint || '/api/resource'}', authenticateToken, (req, res) => {\n  if (req.user.id !== resource.ownerId && !req.user.isAdmin) {\n    return res.status(403).json({ error: 'Forbidden' });\n  }\n  return res.json(resource);\n});`,
        unit_test_code: `// Automated Security Validation Test\nit('should reject unauthorized cross-tenant access with 403', async () => {\n  const res = await request(app).get('${affected_endpoint || '/api/resource'}').set('Authorization', 'Bearer unauthorized_token');\n  expect(res.status).toBe(403);\n});`,
        security_best_practices: [
          'Enforce strict server-side access control validation on every object request.',
          'Never rely on client-supplied identifiers without session ownership verification.',
        ],
      },
    });
  } catch (e: any) {
    console.error('Error in /api/ai/generate-patch:', e);
    res.status(500).json({ error: 'Failed to generate patch' });
  }
});

// ============================================================================
// API: Evidence Validation & Hypothesis Evaluation
// ============================================================================
app.post('/api/evidence/validate', (req, res) => {
  try {
    const { hypothesis, evidenceList = [], sourceFiles = [] } = req.body;
    if (!hypothesis) {
      return res.status(400).json({ success: false, error: 'Hypothesis required for validation' });
    }

    const evaluation = serverValidationEngine.validate(hypothesis, evidenceList, sourceFiles);
    res.json({ success: true, evaluation });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: Finding Correlation & Deduplication
// ============================================================================
app.post('/api/findings/correlate', (req, res) => {
  try {
    const { findings = [] } = req.body;
    const correlated = serverFindingCorrelator.correlate(findings);
    res.json({ success: true, count: correlated.length, findings: correlated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: Risk Engine Evaluation & Metrics
// ============================================================================
app.post('/api/risk/evaluate', (req, res) => {
  try {
    const { findings = [], testPlan, profile, verifiedDefenses = [] } = req.body;
    const evaluation = riskEngine.calculateScanSummary(findings, testPlan, profile, verifiedDefenses);
    res.json({ success: true, ...evaluation });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: Final Report Generation from Validated Findings & Risk Engine
// ============================================================================
app.post('/api/reports/generate', (req, res) => {
  try {
    const { scanState } = req.body;
    if (!scanState) {
      return res.status(400).json({ success: false, error: 'scanState is required to generate report' });
    }

    const report = reportGenerator.generateReport(scanState);

    // Record scan snapshot into project security history
    if (scanState.project_id) {
      historyService.recordScanSnapshot({
        scan_id: scanState.scan_id,
        project_id: scanState.project_id,
        version_id: scanState.version_id || 'v1',
        project_hash: scanState.project_hash || 'sha256-default',
        findings: scanState.findings || [],
        verified_defenses: scanState.verified_defenses || [],
        overall_risk_score: report.results_summary.overall_risk_score,
      });
    }

    res.json({ success: true, report });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: Project Security History & Version Comparison
// ============================================================================
app.get('/api/projects/:id/history', (req, res) => {
  try {
    const history = historyService.getProjectHistory(req.params.id);
    res.json({ success: true, history });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

app.post('/api/projects/record', (req, res) => {
  try {
    const { scan_id, project_id, version_id, project_hash, findings, verified_defenses, overall_risk_score } = req.body;
    const snapshot = historyService.recordScanSnapshot({
      scan_id: scan_id || `scan-${Date.now()}`,
      project_id: project_id || 'proj-shop-app',
      version_id: version_id || 'v1',
      project_hash: project_hash || 'sha256-default',
      findings: findings || [],
      verified_defenses: verified_defenses || [],
      overall_risk_score: overall_risk_score || 0,
    });
    res.json({ success: true, snapshot });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

app.post('/api/projects/compare', (req, res) => {
  try {
    const {
      projectId,
      currentScanId,
      previousScanId,
      currentVersionId,
      previousVersionId,
      currentFindings,
      currentProjectHash,
    } = req.body;

    if (!projectId) {
      return res.status(400).json({ success: false, error: 'projectId is required for version comparison' });
    }

    const diff = historyService.compareScans({
      projectId,
      currentScanId,
      previousScanId,
      currentVersionId,
      previousVersionId,
      currentFindings,
      currentProjectHash,
    });

    res.json({ success: true, diff });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ============================================================================
// API: Automated Security Scan & Architecture Test Suite (Tests 1 - 10)
// ============================================================================
app.post('/api/tests/run-suite', async (req, res) => {
  try {
    const report = await architectureTestSuite.runFullSuite();
    res.json({ success: true, report });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', server_time: new Date().toISOString() });
});

// Vite Middleware & Static Serving
async function start() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
    app.use('*', async (req, res, next) => {
      const url = req.originalUrl;
      try {
        let template = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8');
        template = await vite.transformIndexHtml(url, template);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
      } catch (e) {
        next(e);
      }
    });
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Autonomous Red Team] Engine running at:`);
    console.log(`  > Local:   http://localhost:${PORT}`);
    console.log(`  > Network: http://127.0.0.1:${PORT}`);
  });
}

start();
