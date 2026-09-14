import { ApplicationProfile, AttackSurfaceMap, AttackVector, ScanMode } from '../types';

export function mapAttackSurface(
  profile: ApplicationProfile,
  target: string,
  mode: ScanMode
): AttackSurfaceMap {
  const attackVectors: AttackVector[] = [];

  const exposedSurfaces = {
    file_upload: profile.has_file_upload,
    jwt_tokens: profile.has_jwt,
    session_cookies: profile.has_sessions || profile.has_cookies,
    database_access: profile.database_technologies.length > 0 || profile.has_raw_sql_queries,
    external_http_calls: profile.has_external_requests,
    command_execution: profile.has_command_execution,
    template_rendering: profile.has_templates,
    deserialization: profile.has_deserialization,
    graphql_api: profile.has_graphql,
    admin_endpoints: profile.has_admin_routes,
    unauthenticated_routes: profile.api_endpoints.some((e) => !e.auth_required) || profile.routes_count > 0,
    api_parameters: profile.input_sources.length > 0 || profile.routes_count > 0,
    cors_exposure: true, // evaluated for all web targets
  };

  // 1. API Endpoints & Parameter Handling
  if (profile.api_endpoints.length > 0) {
    for (const ep of profile.api_endpoints.slice(0, 15)) {
      attackVectors.push({
        id: `vec-route-${ep.method.toLowerCase()}-${ep.path.replace(/[^a-zA-Z0-9]/g, '_')}`,
        name: `HTTP Route Exposure: ${ep.method} ${ep.path}`,
        category: 'API & Route Surface',
        description: `Discovered active endpoint accepting HTTP ${ep.method} requests with ${ep.auth_required ? 'authentication required' : 'public unauthenticated access'}.`,
        discovered_location: `${ep.method} ${ep.path}`,
        relevance_score: ep.auth_required ? 70 : 90,
        rationale: ep.auth_required
          ? 'Requires testing for broken object level authorization (BOLA/IDOR) and privilege escalation.'
          : 'Publicly reachable entry point; primary candidate for input validation and injection testing.',
      });
    }
  } else {
    // Default surface for black-box url target
    attackVectors.push({
      id: 'vec-public-web-entry',
      name: 'Public Web Application Root Surface',
      category: 'Web Perimeter',
      description: `Primary HTTP ingress endpoint at ${target}`,
      discovered_location: target,
      relevance_score: 95,
      rationale: 'Core public entrance point for web security testing and crawl.',
    });
  }

  // 2. File Upload Surface
  if (exposedSurfaces.file_upload) {
    attackVectors.push({
      id: 'vec-file-upload',
      name: 'Multipart File Upload Handler',
      category: 'File Operations & Storage',
      description: 'Application contains multipart parser / file upload handler functionality.',
      discovered_location: 'Multipart file endpoints / multer middleware',
      relevance_score: 95,
      rationale: 'Active file upload handler present. Testing for unrestricted file type upload, path traversal, and malicious file execution is highly relevant.',
    });
  }

  // 3. Authentication & JWT Surface
  if (exposedSurfaces.jwt_tokens) {
    attackVectors.push({
      id: 'vec-jwt-tokens',
      name: 'JSON Web Token (JWT) Handling',
      category: 'Authentication & Session',
      description: 'Application utilizes JWT for user authentication, claims, or stateless sessions.',
      discovered_location: 'Authorization: Bearer headers & token handlers',
      relevance_score: 90,
      rationale: 'JWT authentication identified. Testing for weak signing keys, algorithm confusion (none/HS256), and signature verification is relevant.',
    });
  }

  if (exposedSurfaces.session_cookies) {
    attackVectors.push({
      id: 'vec-session-cookies',
      name: 'Stateful Session Cookies',
      category: 'Authentication & Session',
      description: 'Application issues session cookies to maintain state.',
      discovered_location: 'Set-Cookie headers / session middleware',
      relevance_score: 85,
      rationale: 'Session cookies detected. Testing cookie security flags (HttpOnly, Secure, SameSite) and session fixation is relevant.',
    });
  }

  // 4. Database Access & Query Sinks
  if (exposedSurfaces.database_access) {
    attackVectors.push({
      id: 'vec-database-layer',
      name: `Database Layer (${profile.database_technologies.join(', ') || 'SQL/NoSQL'})`,
      category: 'Data Storage & Persistence',
      description: `Data storage interactions identified using ${profile.database_technologies.join(', ') || 'database driver'}.`,
      discovered_location: 'Database client handlers & queries',
      relevance_score: profile.has_raw_sql_queries ? 95 : 75,
      rationale: profile.has_raw_sql_queries
        ? 'Raw SQL concatenation or dynamic query formatting detected in code; high priority for injection testing.'
        : 'ORM / Database integration detected; test parameter binding and query safety.',
    });
  }

  // 5. External HTTP & Outbound Requests (SSRF)
  if (exposedSurfaces.external_http_calls) {
    attackVectors.push({
      id: 'vec-external-requests',
      name: 'Outbound HTTP Client / Proxying',
      category: 'Network & Integrations',
      description: 'Application performs outbound HTTP requests to external or user-supplied URLs.',
      discovered_location: 'HTTP client handlers (axios/fetch/requests)',
      relevance_score: 90,
      rationale: 'Outbound request functions detected. Relevant for Server-Side Request Forgery (SSRF) and webhook verification.',
    });
  }

  // 6. Command Execution
  if (exposedSurfaces.command_execution) {
    attackVectors.push({
      id: 'vec-command-exec',
      name: 'System Command Execution Sinks',
      category: 'OS & System Execution',
      description: 'Application interacts with operating system processes / shell execution.',
      discovered_location: 'child_process / os.system / subprocess calls',
      relevance_score: 98,
      rationale: 'OS execution functions present in codebase. Critical vector for command injection testing.',
    });
  }

  // 7. Template Engine
  if (exposedSurfaces.template_rendering) {
    attackVectors.push({
      id: 'vec-template-rendering',
      name: `Server-Side Template Engine (${profile.template_engine || 'Templates'})`,
      category: 'View Layer & Rendering',
      description: `Server renders dynamic templates using ${profile.template_engine || 'template engine'}.`,
      discovered_location: 'Template view renders',
      relevance_score: 85,
      rationale: 'Dynamic template rendering detected. Relevant for Server-Side Template Injection (SSTI).',
    });
  }

  // 8. Admin / Privileged Endpoints
  if (exposedSurfaces.admin_endpoints) {
    attackVectors.push({
      id: 'vec-admin-routes',
      name: 'Privileged / Administrative Routes',
      category: 'Access Control',
      description: 'Endpoints or code paths dedicated to administrator operations.',
      discovered_location: 'Admin routes & controllers',
      relevance_score: 90,
      rationale: 'Privileged operations present. Testing for broken function-level authorization and privilege bypass is relevant.',
    });
  }

  return {
    target,
    mode,
    generated_at: new Date().toISOString(),
    attack_vectors: attackVectors,
    exposed_surfaces: exposedSurfaces,
    total_attack_vectors_count: attackVectors.length,
  };
}
