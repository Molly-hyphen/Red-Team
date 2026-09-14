import { computeProjectHash } from './fingerprintService.js';
import { profileApplication } from './applicationProfiler.js';
import { riskEngine } from './riskEngine.js';
import { reportGenerator } from './reportGenerator.js';
import { sourceLocationResolver, ProjectSnapshot } from './sourceLocationResolver.js';
import { scanSourceFilesForVulnerabilities } from './sastScanner.js';
import { buildGreyBoxAssessment } from './greyBoxEngine.js';
import {
  TestSuiteReport,
  TestSuiteTestCase,
  Finding,
  SourceFile,
  ScanState,
} from '../src/types.js';

function createMockFinding(partial: Partial<Finding> & { id: string; scan_id: string; title: string; vulnerability_type: string; cwe: string; severity: Finding['severity'] }): Finding {
  return {
    confidence: 0.9,
    cvss_score: 8.0,
    status: 'CONFIRMED',
    owasp_category: 'A01:2021-Broken Access Control',
    affected_asset: 'API Server',
    affected_endpoint: '/api/endpoint',
    description: 'Vulnerability discovered during security evaluation.',
    impact: 'Potential data disclosure or unauthorized access.',
    reproduction_steps: ['Send payload to endpoint.'],
    remediation: 'Implement proper validation and authorization.',
    validation_status: 'validated',
    discovered_by: 'SASTAgent',
    evidence: [],
    ...partial,
  };
}

function createSourceFile(path: string, content: string): SourceFile {
  const parts = path.split('/');
  const name = parts[parts.length - 1] || path;
  return {
    name,
    path,
    content,
  };
}

export class ArchitectureTestSuite {
  public async runFullSuite(): Promise<TestSuiteReport> {
    const tests: TestSuiteTestCase[] = [];

    // -------------------------------------------------------------
    // TEST 1: PYTHON SOURCE LOCATION VERIFICATION (app.py:136 with genuine snippet)
    // -------------------------------------------------------------
    const t1Start = Date.now();
    const pythonLines: string[] = [];
    for (let i = 1; i <= 135; i++) {
      pythonLines.push(`# Line ${i}: configuration and setup code`);
    }
    pythonLines.push("cursor.execute(f\"SELECT * FROM users WHERE org_id = '{org_id}' AND email = '{email}'\")");
    pythonLines.push("return cursor.fetchall()");
    const pythonAppContent = pythonLines.join('\n');

    const pythonFiles: SourceFile[] = [
      createSourceFile('app.py', pythonAppContent),
      createSourceFile('requirements.txt', 'flask==3.0.0\npsycopg2-binary==2.9.9\n'),
    ];
    const pyFingerprint = computeProjectHash(pythonFiles, 'python-sec-app', 'white_box');
    const pySnapshot: ProjectSnapshot = {
      project_id: 'proj-python',
      project_version_id: 'v1',
      scan_id: 'scan-py-1',
      project_sha: pyFingerprint.project_hash,
      files: pythonFiles,
      mode: 'white_box',
    };

    const pyFinding: Finding = createMockFinding({
      id: 'f-py-1',
      scan_id: 'scan-py-1',
      title: 'SQL Injection in user lookup',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
      affected_asset: 'python-sec-app',
      file: 'app.py',
      line: 136,
      source_locations: [
        {
          file: 'app.py',
          line_number: 136,
          snippet: "cursor.execute(f\"SELECT * FROM users WHERE org_id = '{org_id}' AND email = '{email}'\")",
        },
      ],
    });

    const resolvedPyFinding = sourceLocationResolver.resolveFindingSourceLocations(pyFinding, pySnapshot);
    const t1Passed =
      resolvedPyFinding.source_verification_status === 'VERIFIED' &&
      resolvedPyFinding.source_locations !== undefined &&
      resolvedPyFinding.source_locations.length === 1 &&
      resolvedPyFinding.source_locations[0].line_number === 136 &&
      resolvedPyFinding.source_locations[0].verification_status === 'VERIFIED' &&
      resolvedPyFinding.project_sha === pyFingerprint.project_hash;

    tests.push({
      id: 'test-1',
      test_number: 1,
      name: 'TEST 1 — PYTHON SOURCE LOCATION VERIFICATION',
      description: 'Verify authentic Python finding at exact file (app.py:136) against uploaded project snapshot.',
      expected_outcome: 'Source location verified, status marked VERIFIED, bound to exact project SHA.',
      actual_outcome: `Verification Status: ${resolvedPyFinding.source_verification_status}, Line: ${resolvedPyFinding.source_locations?.[0]?.line_number}, Hash: ${resolvedPyFinding.project_sha?.substring(0, 10)}.`,
      passed: t1Passed,
      duration_ms: Date.now() - t1Start,
      details: { resolvedPyFinding },
    });

    // -------------------------------------------------------------
    // TEST 2: WRONG LLM LINE NUMBERS (LLM claims line 136, actual is line 20)
    // -------------------------------------------------------------
    const t2Start = Date.now();
    const pyLines2: string[] = [];
    for (let i = 1; i <= 19; i++) {
      pyLines2.push(`# Line ${i}: setup`);
    }
    pyLines2.push("cursor.execute(f\"SELECT * FROM orders WHERE id = '{order_id}'\")");
    for (let i = 21; i <= 200; i++) {
      pyLines2.push(`# Line ${i}: trailing code`);
    }
    const pyApp2Content = pyLines2.join('\n');
    const pyFiles2: SourceFile[] = [createSourceFile('app.py', pyApp2Content)];
    const pySnapshot2: ProjectSnapshot = {
      project_id: 'proj-py-line-adjust',
      project_version_id: 'v1',
      scan_id: 'scan-py-2',
      project_sha: computeProjectHash(pyFiles2, 'app', 'white_box').project_hash,
      files: pyFiles2,
      mode: 'white_box',
    };

    const wrongLineFinding: Finding = createMockFinding({
      id: 'f-wrong-line',
      scan_id: 'scan-py-2',
      title: 'SQL Injection in order lookup',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'high',
      affected_asset: 'app',
      file: 'app.py',
      line: 136, // LLM hallucinated line 136
      source_locations: [
        {
          file: 'app.py',
          line_number: 136, // LLM guess
          snippet: "cursor.execute(f\"SELECT * FROM orders WHERE id = '{order_id}'\")", // genuine snippet located at line 20
        },
      ],
    });

    const resolvedWrongLine = sourceLocationResolver.resolveFindingSourceLocations(wrongLineFinding, pySnapshot2);
    const t2Passed =
      resolvedWrongLine.source_verification_status === 'VERIFIED' &&
      resolvedWrongLine.source_locations !== undefined &&
      resolvedWrongLine.source_locations[0].line_number === 20 &&
      resolvedWrongLine.source_locations[0].verification_status === 'VERIFIED';

    tests.push({
      id: 'test-2',
      test_number: 2,
      name: 'TEST 2 — WRONG LLM LINE NUMBERS (AUTOMATIC CORRECTION)',
      description: 'LLM hallucinates line 136, but exact code snippet resides at line 20 in source file.',
      expected_outcome: 'Resolver inspects source AST, identifies actual line 20, corrects line number and verifies.',
      actual_outcome: `Original LLM Line: 136 -> Corrected Line: ${resolvedWrongLine.source_locations?.[0]?.line_number}, Verification Status: ${resolvedWrongLine.source_verification_status}.`,
      passed: t2Passed,
      duration_ms: Date.now() - t2Start,
      details: { resolvedWrongLine },
    });

    // -------------------------------------------------------------
    // TEST 3: NONEXISTENT FILE REJECTION
    // -------------------------------------------------------------
    const t3Start = Date.now();
    const nonExistentFileFinding: Finding = createMockFinding({
      id: 'f-fake-file',
      scan_id: 'scan-py-1',
      title: 'Hallucinated flaw in non-existent auth controller',
      vulnerability_type: 'Broken Authentication',
      cwe: 'CWE-287',
      severity: 'critical',
      status: 'POTENTIAL',
      affected_asset: 'python-sec-app',
      file: 'src/controllers/auth_controller.ts', // Does not exist in project
      line: 42,
      source_locations: [
        {
          file: 'src/controllers/auth_controller.ts',
          line_number: 42,
          snippet: 'jwt.verify(token, "hardcoded_secret")',
        },
      ],
    });

    const resolvedFakeFile = sourceLocationResolver.resolveFindingSourceLocations(nonExistentFileFinding, pySnapshot);
    const t3Passed =
      resolvedFakeFile.source_verification_status === 'UNVERIFIED' &&
      (resolvedFakeFile.source_locations === undefined ||
        resolvedFakeFile.source_locations.length === 0 ||
        resolvedFakeFile.source_locations.every((l) => l.verification_status === 'UNVERIFIED'));

    tests.push({
      id: 'test-3',
      test_number: 3,
      name: 'TEST 3 — NONEXISTENT FILE REJECTION',
      description: 'Candidate finding points to a file not present in scanned project files.',
      expected_outcome: 'Marked UNVERIFIED, unverified rationale provided, fabricated file rejected.',
      actual_outcome: `Verification Status: ${resolvedFakeFile.source_verification_status}, Rationale: ${resolvedFakeFile.source_locations?.[0]?.verification_rationale || 'File not found in project snapshot'}.`,
      passed: t3Passed,
      duration_ms: Date.now() - t3Start,
      details: { resolvedFakeFile },
    });

    // -------------------------------------------------------------
    // TEST 4: WRONG LANGUAGE REJECTION (NO TYPESCRIPT IN PYTHON PROJECT)
    // -------------------------------------------------------------
    const t4Start = Date.now();
    const pythonProfile = profileApplication(pythonFiles, 'python-sec-app', 'white_box');
    const wrongLangFinding: Finding = createMockFinding({
      id: 'f-wrong-lang',
      scan_id: 'scan-py-1',
      title: 'TypeScript Prototype Pollution in Python codebase',
      vulnerability_type: 'Prototype Pollution',
      cwe: 'CWE-1321',
      severity: 'high',
      status: 'POTENTIAL',
      affected_asset: 'python-sec-app',
      file: 'src/utils/merge.ts', // TypeScript file in pure Python app
      line: 15,
      source_locations: [
        {
          file: 'src/utils/merge.ts',
          line_number: 15,
          snippet: 'Object.assign(target, source)',
        },
      ],
    });

    const resolvedWrongLang = sourceLocationResolver.resolveFindingSourceLocations(wrongLangFinding, pySnapshot);
    const t4Passed =
      pythonProfile.languages.includes('Python') &&
      !pythonProfile.languages.includes('TypeScript') &&
      resolvedWrongLang.source_verification_status === 'UNVERIFIED' &&
      resolvedWrongLang.source_locations?.[0]?.verification_status === 'UNVERIFIED';

    tests.push({
      id: 'test-4',
      test_number: 4,
      name: 'TEST 4 — WRONG LANGUAGE REJECTION',
      description: 'Attempt to report a TypeScript finding on a pure Python project.',
      expected_outcome: 'Language gating rejects .ts file; marked UNVERIFIED with language mismatch note.',
      actual_outcome: `Project Languages: [${pythonProfile.languages.join(', ')}], Finding Status: ${resolvedWrongLang.source_verification_status}.`,
      passed: t4Passed,
      duration_ms: Date.now() - t4Start,
      details: { resolvedWrongLang, languages: pythonProfile.languages },
    });

    // -------------------------------------------------------------
    // TEST 5: SAME SNIPPET IN ANOTHER PROJECT (STRICT PROJECT SHA ISOLATION)
    // -------------------------------------------------------------
    const t5Start = Date.now();
    const identicalSnippet = "cursor.execute(f\"SELECT * FROM users WHERE org_id = '{org_id}'\")";
    const projAFiles: SourceFile[] = [
      createSourceFile('app.py', `# Project A\n${identicalSnippet}\n`),
      createSourceFile('package.json', '{"name": "project-a"}'),
    ];
    const projBFiles: SourceFile[] = [
      createSourceFile('app.py', `# Project B\n${identicalSnippet}\n`),
      createSourceFile('package.json', '{"name": "project-b-different"}'),
    ];

    const snapA: ProjectSnapshot = {
      project_id: 'proj-a',
      project_version_id: 'v1',
      scan_id: 'scan-a',
      project_sha: computeProjectHash(projAFiles, 'proj-a', 'white_box').project_hash,
      files: projAFiles,
      mode: 'white_box',
    };
    const snapB: ProjectSnapshot = {
      project_id: 'proj-b',
      project_version_id: 'v1',
      scan_id: 'scan-b',
      project_sha: computeProjectHash(projBFiles, 'proj-b', 'white_box').project_hash,
      files: projBFiles,
      mode: 'white_box',
    };

    const findingTemplate: Finding = createMockFinding({
      id: 'f-sqli-template',
      scan_id: '',
      title: 'SQL Injection in user query',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
      affected_asset: 'app',
      file: 'app.py',
      line: 2,
      source_locations: [{ file: 'app.py', line_number: 2, snippet: identicalSnippet }],
    });

    const findingA = sourceLocationResolver.resolveFindingSourceLocations({ ...findingTemplate, scan_id: 'scan-a' }, snapA);
    const findingB = sourceLocationResolver.resolveFindingSourceLocations({ ...findingTemplate, id: 'f-b', scan_id: 'scan-b' }, snapB);

    const t5Passed =
      snapA.project_sha !== snapB.project_sha &&
      findingA.project_sha === snapA.project_sha &&
      findingB.project_sha === snapB.project_sha &&
      findingA.project_sha !== findingB.project_sha &&
      findingA.source_verification_status === 'VERIFIED' &&
      findingB.source_verification_status === 'VERIFIED';

    tests.push({
      id: 'test-5',
      test_number: 5,
      name: 'TEST 5 — SAME SNIPPET IN ANOTHER PROJECT (DETERMINISTIC SHA BINDING)',
      description: 'Identical code snippet scanned in two distinct projects.',
      expected_outcome: 'Each finding is strictly bound to its own project SHA and cannot be conflated.',
      actual_outcome: `Project A SHA: ${findingA.project_sha?.substring(0, 8)}, Project B SHA: ${findingB.project_sha?.substring(0, 8)}, Unique: ${findingA.project_sha !== findingB.project_sha}.`,
      passed: t5Passed,
      duration_ms: Date.now() - t5Start,
      details: { findingA, findingB },
    });

    // -------------------------------------------------------------
    // TEST 6: VERSION CHANGES (V1 LINE 10 -> V2 LINE 40 RESOLUTION)
    // -------------------------------------------------------------
    const t6Start = Date.now();
    const v1Content = Array.from({ length: 9 }, (_, i) => `# v1 header ${i + 1}`).join('\n') +
      "\ndb.query('SELECT * FROM data WHERE id = ' + req.id);\n";
    const v2Content = Array.from({ length: 39 }, (_, i) => `# v2 refactored header ${i + 1}`).join('\n') +
      "\ndb.query('SELECT * FROM data WHERE id = ' + req.id);\n";

    const v1Files: SourceFile[] = [createSourceFile('server.js', v1Content)];
    const v2Files: SourceFile[] = [createSourceFile('server.js', v2Content)];

    const snapV1: ProjectSnapshot = {
      project_id: 'proj-ver',
      project_version_id: 'v1',
      scan_id: 'scan-v1',
      project_sha: computeProjectHash(v1Files, 'proj-ver', 'white_box').project_hash,
      files: v1Files,
      mode: 'white_box',
    };
    const snapV2: ProjectSnapshot = {
      project_id: 'proj-ver',
      project_version_id: 'v2',
      scan_id: 'scan-v2',
      project_sha: computeProjectHash(v2Files, 'proj-ver', 'white_box').project_hash,
      files: v2Files,
      mode: 'white_box',
    };

    const staleV1Finding: Finding = createMockFinding({
      id: 'f-stale-v1',
      scan_id: 'scan-v2',
      title: 'SQL Injection in data query',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'high',
      affected_asset: 'server',
      file: 'server.js',
      line: 10, // Old v1 line
      source_locations: [
        {
          file: 'server.js',
          line_number: 10, // Old line number
          snippet: "db.query('SELECT * FROM data WHERE id = ' + req.id);",
        },
      ],
    });

    const resolvedV2Finding = sourceLocationResolver.resolveFindingSourceLocations(staleV1Finding, snapV2);
    const t6Passed =
      snapV1.project_sha !== snapV2.project_sha &&
      resolvedV2Finding.source_verification_status === 'VERIFIED' &&
      resolvedV2Finding.source_locations?.[0]?.line_number === 40 &&
      resolvedV2Finding.project_sha === snapV2.project_sha;

    tests.push({
      id: 'test-6',
      test_number: 6,
      name: 'TEST 6 — VERSION CHANGES (CORRECT SNAPSHOT BINDING)',
      description: 'Scan Version 2 when line shifted from line 10 to line 40 after refactoring.',
      expected_outcome: 'Resolver resolves exact line 40 against v2 snapshot, binds v2 project_sha.',
      actual_outcome: `V1 Line: 10 -> Resolved V2 Line: ${resolvedV2Finding.source_locations?.[0]?.line_number}, Version SHA: ${resolvedV2Finding.project_sha?.substring(0, 8)}.`,
      passed: t6Passed,
      duration_ms: Date.now() - t6Start,
      details: { resolvedV2Finding },
    });

    // -------------------------------------------------------------
    // TEST 7: CROSS-PROJECT LEAKAGE PREVENTION
    // -------------------------------------------------------------
    const t7Start = Date.now();
    const projSecretFiles: SourceFile[] = [createSourceFile('secret_finance.py', 'DB_PASSWORD = "super_secret_bank_key_999"')];
    const projPublicFiles: SourceFile[] = [createSourceFile('public_blog.py', 'print("Welcome to public blog")')];

    const snapPublic: ProjectSnapshot = {
      project_id: 'proj-blog',
      project_version_id: 'v1',
      scan_id: 'scan-blog',
      project_sha: computeProjectHash(projPublicFiles, 'proj-blog', 'white_box').project_hash,
      files: projPublicFiles,
      mode: 'white_box',
    };

    const leakedFinding: Finding = createMockFinding({
      id: 'f-leaked',
      scan_id: 'scan-blog',
      title: 'Hardcoded Secret in bank configuration',
      vulnerability_type: 'Hardcoded Secrets',
      cwe: 'CWE-798',
      severity: 'critical',
      affected_asset: 'public-blog',
      file: 'secret_finance.py',
      line: 1,
      source_locations: [{ file: 'secret_finance.py', line_number: 1, snippet: 'DB_PASSWORD = "super_secret_bank_key_999"' }],
    });

    const crossProjectResult = sourceLocationResolver.resolveFindingSourceLocations(leakedFinding, snapPublic);
    const t7Passed =
      crossProjectResult.source_verification_status === 'UNVERIFIED' &&
      (crossProjectResult.source_locations === undefined ||
        crossProjectResult.source_locations.length === 0 ||
        crossProjectResult.source_locations[0].verification_status === 'UNVERIFIED');

    tests.push({
      id: 'test-7',
      test_number: 7,
      name: 'TEST 7 — CROSS-PROJECT LEAKAGE PREVENTION',
      description: 'Attempt to attach finding from Project A (Bank) to Project B (Public Blog).',
      expected_outcome: 'Resolver verifies against Project B snapshot, rejects non-existent file/snippet with UNVERIFIED.',
      actual_outcome: `Verification Status: ${crossProjectResult.source_verification_status}, Leaked File Detected: false.`,
      passed: t7Passed,
      duration_ms: Date.now() - t7Start,
      details: { crossProjectResult },
    });

    // -------------------------------------------------------------
    // TEST 8: BLACK BOX FINDINGS (NO SOURCE LOCATIONS / NOT_AVAILABLE)
    // -------------------------------------------------------------
    const t8Start = Date.now();
    const blackBoxSnapshot: ProjectSnapshot = {
      project_id: 'black-box-target',
      project_version_id: 'v1',
      scan_id: 'scan-bb-1',
      project_sha: 'sha256-black-box-target',
      files: [],
      mode: 'black_box',
    };

    const blackBoxFinding: Finding = createMockFinding({
      id: 'f-bb-1',
      scan_id: 'scan-bb-1',
      title: 'SQL Injection on web search parameter',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'high',
      affected_asset: 'https://example.com',
      affected_endpoint: 'https://example.com/search?q=test',
      source_locations: [
        {
          file: 'server.js',
          line_number: 55,
          snippet: 'db.query(req.query.q)',
        },
      ],
    });

    const resolvedBBFinding = sourceLocationResolver.resolveFindingSourceLocations(blackBoxFinding, blackBoxSnapshot);
    const t8Passed =
      resolvedBBFinding.source_verification_status === 'NOT_AVAILABLE' &&
      (resolvedBBFinding.source_locations === undefined || resolvedBBFinding.source_locations.length === 0);

    tests.push({
      id: 'test-8',
      test_number: 8,
      name: 'TEST 8 — BLACK BOX FINDINGS (SOURCE LOCATION UNAVAILABLE)',
      description: 'External Black Box penetration scan where source code is not accessible.',
      expected_outcome: 'Source locations stripped, source_verification_status set to NOT_AVAILABLE.',
      actual_outcome: `Verification Status: ${resolvedBBFinding.source_verification_status}, Source Locations Count: ${resolvedBBFinding.source_locations?.length || 0}.`,
      passed: t8Passed,
      duration_ms: Date.now() - t8Start,
      details: { resolvedBBFinding },
    });

    // -------------------------------------------------------------
    // TEST 9: GITHUB REPO COMMIT BINDING
    // -------------------------------------------------------------
    const t9Start = Date.now();
    const ghCommitSha = '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b';
    const ghRepoFiles: SourceFile[] = [
      createSourceFile('src/api/auth.js', "const secret = 'jwt-super-secret-key-12345';\nmodule.exports = { secret };\n"),
    ];

    const ghSnapshot: ProjectSnapshot = {
      project_id: 'octocat/security-demo',
      project_version_id: 'v1',
      scan_id: 'scan-gh-1',
      project_sha: computeProjectHash(ghRepoFiles, 'octocat/security-demo', 'white_box').project_hash,
      files: ghRepoFiles,
      repoMetadata: {
        owner: 'octocat',
        name: 'security-demo',
        full_name: 'octocat/security-demo',
        branch: 'main',
        commit_sha: ghCommitSha,
      },
      mode: 'white_box',
    };

    const ghFinding: Finding = createMockFinding({
      id: 'f-gh-1',
      scan_id: 'scan-gh-1',
      title: 'Hardcoded Secret in GitHub Repository',
      vulnerability_type: 'Hardcoded Secrets',
      cwe: 'CWE-798',
      severity: 'high',
      affected_asset: 'https://github.com/octocat/security-demo',
      file: 'src/api/auth.js',
      line: 1,
      source_locations: [
        {
          file: 'src/api/auth.js',
          line_number: 1,
          snippet: "const secret = 'jwt-super-secret-key-12345';",
        },
      ],
    });

    const resolvedGHFinding = sourceLocationResolver.resolveFindingSourceLocations(ghFinding, ghSnapshot);
    const loc = resolvedGHFinding.source_locations?.[0];
    const expectedGithubUrl = `https://github.com/octocat/security-demo/blob/${ghCommitSha}/src/api/auth.js#L1`;

    const t9Passed =
      resolvedGHFinding.source_verification_status === 'VERIFIED' &&
      loc !== undefined &&
      loc.verification_status === 'VERIFIED' &&
      loc.commit_sha === ghCommitSha &&
      loc.github_url === expectedGithubUrl;

    tests.push({
      id: 'test-9',
      test_number: 9,
      name: 'TEST 9 — GITHUB REPOSITORY COMMIT BINDING',
      description: 'GitHub repo scan binds source location to immutable commit SHA with permalink.',
      expected_outcome: 'Source location contains exact commit_sha and permalink to GitHub commit line.',
      actual_outcome: `Commit SHA: ${loc?.commit_sha?.substring(0, 10)}..., GitHub URL: ${loc?.github_url}.`,
      passed: t9Passed,
      duration_ms: Date.now() - t9Start,
      details: { resolvedGHFinding },
    });

    // -------------------------------------------------------------
    // TEST 10: SECURE CODE -> 0 CONFIRMED VULNERABILITIES & NO PHANTOM LOCATIONS
    // -------------------------------------------------------------
    const t10Start = Date.now();
    const hardenedFiles: SourceFile[] = [
      createSourceFile(
        'src/server.ts',
        `import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import db from './db';

const app = express();
app.use(helmet());
app.use(rateLimit({ max: 100 }));

app.get('/api/users/:id', async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const user = await db.query('SELECT id, username FROM users WHERE id = $1', [req.params.id]);
  return res.json(user);
});
`
      ),
    ];

    const hardenedProfile = profileApplication(hardenedFiles, 'secure-app', 'white_box');
    const secureSummary = riskEngine.calculateScanSummary([], undefined, hardenedProfile, [
      {
        id: 'def-1',
        category: 'SQL Injection',
        title: 'Parameterized Query Hardening',
        status: 'passed',
        description: 'Queries are strictly parameterized with placeholders.',
        tested_vector: 'SQL Injection probe',
        evidence_summary: 'Verified $1 prepared statement usage in AST.',
      },
    ]);

    const cleanScanState: ScanState = {
      scan_id: 'scan-secure',
      target: 'secure-app',
      mode: 'white_box',
      status: 'completed',
      progress: 100,
      posture_status: 'hardened_resilient',
      technologies: hardenedProfile.languages.concat(hardenedProfile.frameworks),
      endpoints: [{ url: '/api/users/:id', method: 'GET', parameters: ['id'], auth_required: true, source_agent: 'Recon' }],
      findings: [],
      verified_defenses: [
        {
          id: 'def-1',
          category: 'SQL Injection',
          title: 'Parameterized Query Hardening',
          status: 'passed',
          description: 'Queries are strictly parameterized with placeholders.',
          tested_vector: 'SQL Injection probe',
          evidence_summary: 'Verified $1 prepared statement usage in AST.',
        },
      ],
      agents: {},
      events: [],
      started_at: new Date().toISOString(),
    };

    const finalReport = reportGenerator.generateReport(cleanScanState);
    const t10Passed =
      secureSummary.metrics.confirmed_count === 0 &&
      secureSummary.metrics.posture_status === 'hardened_resilient' &&
      finalReport.confirmed_vulnerabilities.length === 0 &&
      finalReport.markdown_report.includes('RESILIENT / HARDENED');

    tests.push({
      id: 'test-10',
      test_number: 10,
      name: 'TEST 10 — SECURE CODE & CLEAN ZERO-FINDINGS VALIDITY',
      description: 'Hardened application analysis yielding 0 confirmed vulnerabilities and no phantom source locations.',
      expected_outcome: '0 confirmed findings, posture status is hardened_resilient, report properly generated.',
      actual_outcome: `Confirmed Flaws: ${finalReport.confirmed_vulnerabilities.length}, Posture: ${secureSummary.metrics.posture_status}.`,
      passed: t10Passed,
      duration_ms: Date.now() - t10Start,
      details: { metrics: secureSummary.metrics },
    });

    // -------------------------------------------------------------
    // TEST 11: AUTHORITATIVE STACK — PURE PYTHON FASTAPI (ZERO-FILE TS ENFORCEMENT)
    // -------------------------------------------------------------
    const t11Start = Date.now();
    const purePyFiles: SourceFile[] = [
      createSourceFile(
        'main.py',
        `from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Payment API")

@app.get("/api/v1/payments/{payment_id}")
def get_payment(payment_id: str):
    return {"payment_id": payment_id, "status": "processed"}
`
      ),
      createSourceFile('requirements.txt', 'fastapi==0.110.0\nuvicorn==0.28.0\npydantic==2.6.4\nsqlalchemy==2.0.28\n'),
    ];

    const pyTechHash = computeProjectHash(purePyFiles, 'python-fastapi-service', 'white_box');
    const pyTechProfile = profileApplication(purePyFiles, 'python-fastapi-service', 'white_box');

    const t11Passed =
      pyTechProfile.languages.includes('Python') &&
      !pyTechProfile.languages.includes('TypeScript') &&
      !pyTechProfile.languages.includes('JavaScript') &&
      pyTechProfile.frameworks.some((f) => f.includes('FastAPI')) &&
      !pyTechProfile.frameworks.some((f) => f.includes('Express')) &&
      pyTechProfile.stack_flags?.has_python === true &&
      pyTechProfile.stack_flags?.has_fastapi === true &&
      pyTechProfile.stack_flags?.has_typescript === false &&
      pyTechProfile.stack_flags?.has_express === false &&
      pyTechHash.detected_technologies?.some((t) => t.name === 'Python' && t.category === 'language') &&
      pyTechHash.undetected_technologies?.some((t) => t.name === 'TypeScript' && t.category === 'language');

    tests.push({
      id: 'test-11',
      test_number: 11,
      name: 'TEST 11 — ZERO-FILE RULE: PURE PYTHON FASTAPI PROJECT',
      description: 'Snapshot with only Python files (.py) and requirements.txt must never report TypeScript or Express.',
      expected_outcome: 'Languages=[Python], Frameworks=[FastAPI], TypeScript=0 files & not detected, Express not detected.',
      actual_outcome: `Languages: [${pyTechProfile.languages.join(', ')}], Frameworks: [${pyTechProfile.frameworks.join(', ')}], TS Flag: ${pyTechProfile.stack_flags?.has_typescript}, Express Flag: ${pyTechProfile.stack_flags?.has_express}.`,
      passed: Boolean(t11Passed),
      duration_ms: Date.now() - t11Start,
      details: { detected: pyTechProfile.detected_technologies, flags: pyTechProfile.stack_flags },
    });

    // -------------------------------------------------------------
    // TEST 12: AUTHORITATIVE STACK — NODE.JS + TYPESCRIPT + EXPRESS
    // -------------------------------------------------------------
    const t12Start = Date.now();
    const nodeTsFiles: SourceFile[] = [
      createSourceFile(
        'src/index.ts',
        `import express from 'express';
const app = express();
app.get('/health', (req, res) => res.json({ ok: true }));
`
      ),
      createSourceFile(
        'package.json',
        JSON.stringify({
          name: 'ts-backend',
          dependencies: { express: '^4.19.2' },
          devDependencies: { typescript: '^5.4.0', '@types/express': '^4.17.21' },
        })
      ),
    ];

    const tsProfile = profileApplication(nodeTsFiles, 'ts-backend', 'white_box');
    const t12Passed =
      tsProfile.languages.includes('TypeScript') &&
      !tsProfile.languages.includes('Python') &&
      !tsProfile.languages.includes('Go') &&
      tsProfile.frameworks.some((f) => f.includes('Express')) &&
      tsProfile.stack_flags?.has_typescript === true &&
      tsProfile.stack_flags?.has_express === true &&
      tsProfile.stack_flags?.has_python === false;

    tests.push({
      id: 'test-12',
      test_number: 12,
      name: 'TEST 12 — AUTHENTIC TYPESCRIPT + EXPRESS IDENTIFICATION',
      description: 'Snapshot containing .ts files and express package.json must accurately report TypeScript and Express.',
      expected_outcome: 'Languages=[TypeScript], Frameworks=[Express.js], has_typescript=true, has_python=false.',
      actual_outcome: `Languages: [${tsProfile.languages.join(', ')}], Frameworks: [${tsProfile.frameworks.join(', ')}], has_typescript: ${tsProfile.stack_flags?.has_typescript}.`,
      passed: Boolean(t12Passed),
      duration_ms: Date.now() - t12Start,
      details: { detected: tsProfile.detected_technologies },
    });

    // -------------------------------------------------------------
    // TEST 13: AUTHORITATIVE STACK — NODE.JS + JAVASCRIPT ONLY (ZERO TS)
    // -------------------------------------------------------------
    const t13Start = Date.now();
    const nodeJsFiles: SourceFile[] = [
      createSourceFile(
        'server.js',
        `const express = require('express');
const app = express();
app.get('/api', (req, res) => res.send('ok'));
`
      ),
      createSourceFile('package.json', JSON.stringify({ name: 'js-service', dependencies: { express: '^4.18.2' } })),
    ];

    const jsProfile = profileApplication(nodeJsFiles, 'js-service', 'white_box');
    const t13Passed =
      jsProfile.languages.includes('JavaScript') &&
      !jsProfile.languages.includes('TypeScript') &&
      jsProfile.stack_flags?.has_typescript === false &&
      jsProfile.stack_flags?.has_javascript === true;

    tests.push({
      id: 'test-13',
      test_number: 13,
      name: 'TEST 13 — ZERO-FILE RULE: PURE JAVASCRIPT (ZERO TS REPORTED)',
      description: 'Pure JS project with 0 .ts/.tsx files must report JavaScript and strictly false for TypeScript.',
      expected_outcome: 'Languages=[JavaScript], has_typescript=false, has_javascript=true.',
      actual_outcome: `Languages: [${jsProfile.languages.join(', ')}], has_typescript: ${jsProfile.stack_flags?.has_typescript}.`,
      passed: Boolean(t13Passed),
      duration_ms: Date.now() - t13Start,
      details: { languages: jsProfile.languages, flags: jsProfile.stack_flags },
    });

    // -------------------------------------------------------------
    // TEST 14: AUTHORITATIVE STACK — POLYGLOT PYTHON + GO (NO TS)
    // -------------------------------------------------------------
    const t14Start = Date.now();
    const polyglotFiles: SourceFile[] = [
      createSourceFile('api/main.py', 'from flask import Flask\napp = Flask(__name__)\n'),
      createSourceFile('requirements.txt', 'flask==3.0.0\n'),
      createSourceFile('worker/main.go', 'package main\nimport "fmt"\nfunc main() { fmt.Println("worker") }\n'),
      createSourceFile('go.mod', 'module example.com/worker\ngo 1.22\n'),
    ];

    const polyProfile = profileApplication(polyglotFiles, 'polyglot-app', 'white_box');
    const t14Passed =
      polyProfile.languages.includes('Python') &&
      polyProfile.languages.includes('Go') &&
      !polyProfile.languages.includes('TypeScript') &&
      !polyProfile.languages.includes('JavaScript') &&
      polyProfile.stack_flags?.has_python === true &&
      polyProfile.stack_flags?.has_go === true &&
      polyProfile.stack_flags?.has_typescript === false;

    tests.push({
      id: 'test-14',
      test_number: 14,
      name: 'TEST 14 — MULTI-LANGUAGE POLYGLOT DETECTION (PYTHON + GO)',
      description: 'Polyglot project with Python API and Go worker must identify both Python and Go without hallucinating TS.',
      expected_outcome: 'Languages=[Python, Go], has_python=true, has_go=true, has_typescript=false.',
      actual_outcome: `Languages: [${polyProfile.languages.join(', ')}], has_go: ${polyProfile.stack_flags?.has_go}, has_typescript: ${polyProfile.stack_flags?.has_typescript}.`,
      passed: Boolean(t14Passed),
      duration_ms: Date.now() - t14Start,
      details: { languages: polyProfile.languages },
    });

    // -------------------------------------------------------------
    // TEST 15: AUTHORITATIVE STACK — IGNORED DIRECTORIES & BUILD ARTIFACTS
    // -------------------------------------------------------------
    const t15Start = Date.now();
    const filesWithIgnoredArtifacts: SourceFile[] = [
      createSourceFile('src/main.py', 'print("real application code")'),
      createSourceFile('requirements.txt', 'requests==2.31.0\n'),
      createSourceFile('node_modules/express/index.js', 'module.exports = {}'), // Ignored dir
      createSourceFile('dist/bundle.js', 'console.log("compiled bundle")'), // Ignored dir
      createSourceFile('.venv/lib/python3.11/site-packages/something.py', '# venv file'), // Ignored dir
    ];

    const ignoredProfile = profileApplication(filesWithIgnoredArtifacts, 'filtered-app', 'white_box');
    const t15Passed =
      ignoredProfile.languages.includes('Python') &&
      !ignoredProfile.languages.includes('JavaScript') &&
      !ignoredProfile.frameworks.some((f) => f.includes('Express')) &&
      ignoredProfile.stack_flags?.has_express === false &&
      ignoredProfile.stack_flags?.has_python === true;

    tests.push({
      id: 'test-15',
      test_number: 15,
      name: 'TEST 15 — ARTIFACT & IGNORED DIRECTORY FILTERING',
      description: 'Files in node_modules/, dist/, and .venv/ must be ignored and not bias technology detection.',
      expected_outcome: 'Languages=[Python], JavaScript and Express filtered out from build/dependency directories.',
      actual_outcome: `Languages: [${ignoredProfile.languages.join(', ')}], Frameworks: [${ignoredProfile.frameworks.join(', ')}].`,
      passed: Boolean(t15Passed),
      duration_ms: Date.now() - t15Start,
      details: { languages: ignoredProfile.languages, frameworks: ignoredProfile.frameworks },
    });

    // -------------------------------------------------------------
    // TEST 16: AUTHORITATIVE STACK — BLACK BOX SCAN (0 FILES SNAPSHOT)
    // -------------------------------------------------------------
    const t16Start = Date.now();
    const blackBoxProfile = profileApplication([], 'https://target-api.corp.internal', 'black_box');
    const blackBoxFingerprint = computeProjectHash([], 'https://target-api.corp.internal', 'black_box');

    const t16Passed =
      blackBoxProfile.languages.includes('Web Application (Remote Target)') &&
      blackBoxProfile.frameworks.includes('HTTP Web Service') &&
      !blackBoxProfile.languages.includes('TypeScript') &&
      !blackBoxProfile.frameworks.includes('Express.js') &&
      blackBoxProfile.stack_flags?.has_typescript === false &&
      blackBoxFingerprint.normalized_files_count === 0;

    tests.push({
      id: 'test-16',
      test_number: 16,
      name: 'TEST 16 — BLACK BOX TARGET PROFILE (NO PHANTOM TECH)',
      description: 'Zero-file Black Box scan must assign generic remote target architecture without hallucinating Node or Express.',
      expected_outcome: 'Languages=[Web Application (Remote Target)], Frameworks=[HTTP Web Service], TS=false.',
      actual_outcome: `Languages: [${blackBoxProfile.languages.join(', ')}], Frameworks: [${blackBoxProfile.frameworks.join(', ')}].`,
      passed: Boolean(t16Passed),
      duration_ms: Date.now() - t16Start,
      details: { profile: blackBoxProfile },
    });

    // -------------------------------------------------------------
    // TEST 17: CROSS-MODE CONSISTENCY (WHITE-BOX vs GRAY-BOX)
    // -------------------------------------------------------------
    const t17Start = Date.now();
    const crossModeFiles: SourceFile[] = [
      createSourceFile('api/server.py', 'from fastapi import FastAPI\napp = FastAPI()\n'),
      createSourceFile('requirements.txt', 'fastapi==0.110.0\n'),
    ];

    const wbProfile = profileApplication(crossModeFiles, 'cross-mode-app', 'white_box');
    const gbProfile = profileApplication(crossModeFiles, 'cross-mode-app', 'gray_box');
    const wbHash = computeProjectHash(crossModeFiles, 'cross-mode-app', 'white_box');
    const gbHash = computeProjectHash(crossModeFiles, 'cross-mode-app', 'gray_box');

    const t17Passed =
      wbHash.project_hash === gbHash.project_hash &&
      wbProfile.languages.join(',') === gbProfile.languages.join(',') &&
      wbProfile.frameworks.join(',') === gbProfile.frameworks.join(',') &&
      wbProfile.stack_flags?.has_fastapi === gbProfile.stack_flags?.has_fastapi &&
      wbProfile.stack_flags?.has_typescript === false &&
      gbProfile.stack_flags?.has_typescript === false;

    tests.push({
      id: 'test-17',
      test_number: 17,
      name: 'TEST 17 — DETERMINISTIC CROSS-MODE STACK CONSISTENCY',
      description: 'Same project files scanned in white_box and gray_box mode must produce identical tech stack fingerprint.',
      expected_outcome: 'Hashes match, languages match [Python], frameworks match [FastAPI], TS is false in both.',
      actual_outcome: `WB Hash == GB Hash: ${wbHash.project_hash === gbHash.project_hash}, Languages: [${wbProfile.languages.join(', ')}].`,
      passed: Boolean(t17Passed),
      duration_ms: Date.now() - t17Start,
      details: { wbHash: wbHash.project_hash, gbHash: gbHash.project_hash },
    });

    // -------------------------------------------------------------
    // TEST 18: FINDING VALIDATION GATING AGAINST AUTHORITATIVE FINGERPRINT
    // -------------------------------------------------------------
    const t18Start = Date.now();
    const pyTargetSnapshot: ProjectSnapshot = {
      project_id: 'py-target',
      project_version_id: 'v1',
      scan_id: 'scan-py-target',
      project_sha: computeProjectHash(purePyFiles, 'py-target', 'white_box').project_hash,
      files: purePyFiles,
      mode: 'white_box',
    };

    // Fabricated finding claiming Node.js Express SQL Injection in non-existent TS file
    const fakeTsFinding: Finding = createMockFinding({
      id: 'f-fake-ts-finding',
      scan_id: 'scan-py-target',
      title: 'Express SQL Injection in auth.ts',
      vulnerability_type: 'SQL Injection',
      cwe: 'CWE-89',
      severity: 'critical',
      affected_asset: 'py-target',
      file: 'src/routes/auth.ts',
      line: 45,
      source_locations: [
        {
          file: 'src/routes/auth.ts',
          line_number: 45,
          snippet: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
        },
      ],
    });

    const gatedResult = sourceLocationResolver.resolveFindingSourceLocations(fakeTsFinding, pyTargetSnapshot);
    const t18Passed =
      gatedResult.source_verification_status === 'UNVERIFIED' &&
      gatedResult.source_locations?.[0]?.verification_status === 'UNVERIFIED' &&
      gatedResult.source_locations?.[0]?.verification_rationale?.toLowerCase().includes('not found');

    tests.push({
      id: 'test-18',
      test_number: 18,
      name: 'TEST 18 — HALLUCINATED FINDING REJECTION VIA SOURCE GATE',
      description: 'Reject finding claiming TypeScript Express vulnerability on a pure Python FastAPI snapshot.',
      expected_outcome: 'Finding marked UNVERIFIED with file-not-found rationale, prevented from being marked CONFIRMED.',
      actual_outcome: `Verification Status: ${gatedResult.source_verification_status}, Rationale: ${gatedResult.source_locations?.[0]?.verification_rationale}.`,
      passed: Boolean(t18Passed),
      duration_ms: Date.now() - t18Start,
      details: { gatedResult },
    });

    // -------------------------------------------------------------
    // TEST 19: ZERO-FILE RULE & SOURCE-GROUNDED SAST SCANNING
    // -------------------------------------------------------------
    const t19Start = Date.now();
    const realPythonRepo: SourceFile[] = [
      createSourceFile('api/routes.py', 'import sqlite3\n\ndef get_user(user_id):\n    conn = sqlite3.connect("app.db")\n    cursor = conn.cursor()\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    return cursor.fetchone()\n'),
      createSourceFile('config.py', 'SECRET_KEY = "super_secret_production_key_12345"\nDEBUG = True\n'),
      createSourceFile('requirements.txt', 'flask==3.0.0\nsqlite3\n'),
    ];

    const sastScanOutput = scanSourceFilesForVulnerabilities(realPythonRepo, 'https://github.com/org/python-app', 'deep_technical');
    const pySnapshot19: ProjectSnapshot = {
      project_id: 'python-app-19',
      project_version_id: 'v1',
      scan_id: 'scan-19',
      project_sha: computeProjectHash(realPythonRepo, 'python-app', 'white_box').project_hash,
      files: realPythonRepo,
      mode: 'white_box',
    };
    const resolvedSastFindings = sourceLocationResolver.resolveAllFindings(sastScanOutput.findings, pySnapshot19);

    // Verify 1: Every single finding references ONLY existing files in realPythonRepo
    const allowedFiles = new Set(realPythonRepo.map((f) => f.path));
    const allFilesExist = resolvedSastFindings.every((f) => {
      const filePath = f.file || f.source_locations?.[0]?.file_path || f.source_locations?.[0]?.file;
      return filePath && allowedFiles.has(filePath);
    });

    // Verify 2: Zero .ts, .js, or Express files exist in any finding
    const noPhantomFiles = resolvedSastFindings.every((f) => {
      const path = (f.file || '') + (f.affected_endpoint || '') + (f.source_locations?.[0]?.file_path || '');
      return !path.includes('.ts') && !path.includes('.js') && !path.includes('routes/users');
    });

    // Verify 3: All findings are VERIFIED
    const allVerified = resolvedSastFindings.length > 0 && resolvedSastFindings.every((f) => f.source_verification_status === 'VERIFIED');

    const t19Passed = allFilesExist && noPhantomFiles && allVerified;

    tests.push({
      id: 'test-19',
      test_number: 19,
      name: 'TEST 19 — ZERO-FILE RULE & SOURCE-GROUNDED SAST',
      description: 'Ensure White-Box SAST scans ONLY uploaded files (Python) with 0 phantom .ts files and 100% verified locations.',
      expected_outcome: 'All findings bound to api/routes.py or config.py, zero .ts files, status=VERIFIED.',
      actual_outcome: `Found ${resolvedSastFindings.length} findings, AllFilesExist=${allFilesExist}, NoPhantomFiles=${noPhantomFiles}, AllVerified=${allVerified}.`,
      passed: Boolean(t19Passed),
      duration_ms: Date.now() - t19Start,
      details: { findings: resolvedSastFindings },
    });

    // -------------------------------------------------------------
    // TEST 20: DECOUPLED GREY-BOX ASSESSMENT (AUTHENTICATED API & LOGIC)
    // -------------------------------------------------------------
    const t20Start = Date.now();
    const gbAssessment = buildGreyBoxAssessment('https://api.enterprise.io', 'api.enterprise.io', 'deep_technical');

    const gbSnapshot: ProjectSnapshot = {
      project_id: 'api.enterprise.io',
      project_version_id: 'v1',
      scan_id: 'scan-gb-20',
      project_sha: 'sha256-gb',
      files: [],
      mode: 'grey_box',
    };
    const resolvedGbFindings = sourceLocationResolver.resolveAllFindings(gbAssessment.findings, gbSnapshot);

    // Verify 1: Zero source locations attached
    const zeroSourceLocations = resolvedGbFindings.every(
      (f) => (!f.source_locations || f.source_locations.length === 0) && f.source_verification_status === 'NOT_AVAILABLE' && !f.file && !f.line
    );

    // Verify 2: Every finding contains authentic HTTP exchange evidence
    const allHaveHttpEvidence = resolvedGbFindings.every(
      (f) => f.evidence && f.evidence.some((e) => e.evidence_type === 'http_exchange' && e.request_data && e.request_data.url)
    );

    // Verify 3: Findings represent API logic flaws (BOLA, BFLA, Mass Assignment, Webhook SSRF, etc.)
    const hasApiLogicFlaws = resolvedGbFindings.some((f) => f.cwe === 'CWE-639' || f.cwe === 'CWE-915' || f.cwe === 'CWE-918' || f.cwe === 'CWE-285');

    const t20Passed = zeroSourceLocations && allHaveHttpEvidence && hasApiLogicFlaws && resolvedGbFindings.length >= 3;

    tests.push({
      id: 'test-20',
      test_number: 20,
      name: 'TEST 20 — DECOUPLED GREY-BOX ASSESSMENT (AUTHENTICATED API)',
      description: 'Ensure Grey-Box mode generates dedicated API/logic flaws with HTTP exchange proof and ZERO source files.',
      expected_outcome: 'Zero source locations, status=NOT_AVAILABLE, all findings have HTTP evidence and API CWEs (BOLA/BFLA/Mass Assignment).',
      actual_outcome: `ZeroSourceLocations=${zeroSourceLocations}, AllHttpEvidence=${allHaveHttpEvidence}, HasApiLogicFlaws=${hasApiLogicFlaws}, FindingsCount=${resolvedGbFindings.length}.`,
      passed: Boolean(t20Passed),
      duration_ms: Date.now() - t20Start,
      details: { findings: resolvedGbFindings },
    });

    const totalTests = tests.length;
    const passedTests = tests.filter((t) => t.passed).length;
    const failedTests = totalTests - passedTests;

    return {
      suite_id: `suite-${Date.now()}`,
      executed_at: new Date().toISOString(),
      total_tests: totalTests,
      passed_tests: passedTests,
      failed_tests: failedTests,
      all_passed: failedTests === 0,
      tests,
    };
  }
}

export const architectureTestSuite = new ArchitectureTestSuite();
