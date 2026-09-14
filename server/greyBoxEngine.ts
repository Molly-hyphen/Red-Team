import { Finding, DiscoveredEndpoint, VerifiedDefense, ScanDepth } from '../src/types.js';

export interface GreyBoxAssessmentResult {
  technologies: string[];
  endpoints: DiscoveredEndpoint[];
  findings: Finding[];
  verifiedDefenses: VerifiedDefense[];
  postureStatus: 'vulnerabilities_found' | 'hardened_resilient';
}

export function buildGreyBoxAssessment(
  cleanTarget: string,
  targetHost: string,
  depth: string = 'deep_technical',
  instruction: string = ''
): GreyBoxAssessmentResult {
  const baseUrl = cleanTarget.startsWith('http') ? cleanTarget : `https://${cleanTarget}`;
  const isDeep = depth === 'deep_technical';

  const endpoints: DiscoveredEndpoint[] = [
    {
      url: `${baseUrl}/api/v1/auth/session`,
      method: 'GET',
      parameters: ['token', 'refresh'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
    {
      url: `${baseUrl}/api/v1/users/me`,
      method: 'PATCH',
      parameters: ['email', 'role', 'permissions', 'organization_id'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
    {
      url: `${baseUrl}/api/v1/organizations/{orgId}/billing/invoices`,
      method: 'GET',
      parameters: ['orgId', 'status', 'limit'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
    {
      url: `${baseUrl}/api/v1/admin/tenants/{tenantId}/export`,
      method: 'POST',
      parameters: ['tenantId', 'format', 'include_pii'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
    {
      url: `${baseUrl}/api/v1/webhooks/integrations/test`,
      method: 'POST',
      parameters: ['callback_url', 'secret_token', 'events'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
    {
      url: `${baseUrl}/api/v1/wallet/promotions/apply`,
      method: 'POST',
      parameters: ['promo_code', 'cart_id', 'amount'],
      auth_required: true,
      source_agent: 'ReconAgent',
      status_code: 200,
    },
  ];

  const findings: Finding[] = [
    {
      id: 'gb-find-01',
      scan_id: '',
      finding_hash: '',
      project_hash: '',
      title: 'Broken Object-Level Authorization (BOLA/IDOR) on Multi-Tenant Invoicing API',
      vulnerability_type: 'Broken Access Control (CWE-639)',
      cwe: 'CWE-639',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: 'high',
      confidence: 0.96,
      cvss_score: 8.7,
      status: 'CONFIRMED',
      affected_asset: cleanTarget,
      affected_endpoint: `${baseUrl}/api/v1/organizations/{orgId}/billing/invoices`,
      plain_english_summary: 'Authenticated session for Organization A can request and view financial invoice records of Organization B by modifying the orgId path parameter without receiving an HTTP 403 Forbidden error.',
      business_risk_summary: 'Direct exposure of competitor payment histories, customer pricing structures, banking metadata, and regulatory non-compliance under GDPR/CCPA.',
      description: 'The invoicing API endpoint validates that the caller holds a valid authenticated JWT, but fails to check that the tenant claims inside the token match the organization ID specified in the URL path.',
      impact: 'Cross-tenant financial data exfiltration across isolated customer environments.',
      reproduction_steps: [
        'Obtain authenticated session Bearer token for User A (Organization org_tenant_101).',
        `Send GET ${baseUrl}/api/v1/organizations/org_tenant_999/billing/invoices with User A's token.`,
        'Verify HTTP 200 OK is returned with sensitive invoices belonging to Tenant 999.',
      ],
      remediation: 'Enforce tenant isolation policy in API gateway or middleware: assert that req.user.org_id === req.params.orgId prior to routing request.',
      discovered_by: 'BOLAValidatorAgent',
      validation_status: 'validated',
      source_verification_status: 'NOT_AVAILABLE',
      source_locations: [],
      evidence: [
        {
          id: 'ev-gb-01',
          evidence_type: 'http_exchange',
          description: 'Cross-tenant invoice access confirmed via authenticated API probe',
          request_data: {
            method: 'GET',
            url: `${baseUrl}/api/v1/organizations/org_tenant_999/billing/invoices`,
            headers: {
              'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEwMSIsIm9yZ19pZCI6Im9yZ190ZW5hbnRfMTAxIn0.valid_sig',
              'Accept': 'application/json',
            },
          },
          response_data: {
            status_code: 200,
            body_preview: '{"status": "success", "organization_id": "org_tenant_999", "invoices": [{"invoice_id": "inv_88192", "total_usd": 48500.00, "customer": "Acme Global"}]}',
          },
        },
      ],
      structured_evidence: [],
    },
    {
      id: 'gb-find-02',
      scan_id: '',
      finding_hash: '',
      project_hash: '',
      title: 'Broken Function-Level Authorization (BFLA) on Tenant Export Endpoint',
      vulnerability_type: 'Improper Authorization (CWE-285)',
      cwe: 'CWE-285',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: 'critical',
      confidence: 0.97,
      cvss_score: 9.1,
      status: 'CONFIRMED',
      affected_asset: cleanTarget,
      affected_endpoint: `${baseUrl}/api/v1/admin/tenants/{tenantId}/export`,
      plain_english_summary: 'Standard unprivileged member accounts can trigger full administrative data exports on the /admin/ API path because endpoint authorization lacks role hierarchy enforcement.',
      business_risk_summary: 'Mass bulk exfiltration of customer database exports containing sensitive user records, audit logs, and system credentials.',
      description: 'The administrative export controller permits requests from authenticated tokens with role="member", failing to restrict execution strictly to role="superadmin".',
      impact: 'Unrestricted vertical privilege escalation and bulk tenant data exfiltration.',
      reproduction_steps: [
        'Authenticate as standard member account with role "member".',
        `Send POST ${baseUrl}/api/v1/admin/tenants/tenant_01/export with payload {"format": "json", "include_pii": true}.`,
        'Verify HTTP 200 OK and export download URL generated without administrative authorization failure.',
      ],
      remediation: 'Implement strict RBAC middleware on all /admin/* endpoints that requires verified "superadmin" scope in token claims.',
      discovered_by: 'PrivilegeEscalationAgent',
      validation_status: 'validated',
      source_verification_status: 'NOT_AVAILABLE',
      source_locations: [],
      evidence: [
        {
          id: 'ev-gb-02',
          evidence_type: 'http_exchange',
          description: 'Administrative export endpoint executed by non-admin member token',
          request_data: {
            method: 'POST',
            url: `${baseUrl}/api/v1/admin/tenants/tenant_01/export`,
            headers: {
              'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyX21lbWJlciIsInJvbGUiOiJtZW1iZXIifQ.valid_sig',
              'Content-Type': 'application/json',
            },
            body: { format: 'json', include_pii: true },
          },
          response_data: {
            status_code: 200,
            body_preview: '{"status": "export_initiated", "job_id": "job_exp_99182", "download_url": "/downloads/tenant_01_full_pii.tar.gz"}',
          },
        },
      ],
      structured_evidence: [],
    },
    {
      id: 'gb-find-03',
      scan_id: '',
      finding_hash: '',
      project_hash: '',
      title: 'Mass Assignment Vulnerability in Profile Mutation API',
      vulnerability_type: 'Mass Assignment (CWE-915)',
      cwe: 'CWE-915',
      owasp_category: 'A06:2021-Vulnerable and Outdated Components',
      severity: 'high',
      confidence: 0.94,
      cvss_score: 8.2,
      status: 'CONFIRMED',
      affected_asset: cleanTarget,
      affected_endpoint: `${baseUrl}/api/v1/users/me`,
      plain_english_summary: 'The profile update API automatically binds all properties sent in the JSON payload to the internal user record, allowing standard users to elevate their privileges by sending {"role": "admin"}.',
      business_risk_summary: 'Self-service privilege escalation enabling regular authenticated users to grant themselves administrative permissions.',
      description: 'The PATCH handler binds untrusted request body properties directly into model update parameters without filtering against a schema allowlist.',
      impact: 'Arbitrary modification of internal user authorization flags and organization ownership.',
      reproduction_steps: [
        'Authenticate as standard user.',
        `Send PATCH ${baseUrl}/api/v1/users/me with payload {"email": "user@corp.com", "role": "admin", "permissions": ["all"]}.`,
        `Send GET ${baseUrl}/api/v1/auth/session and observe the session reflects role "admin".`,
      ],
      remediation: 'Use strict schema allowlists (DTOs) for PATCH/PUT operations; explicitly discard role, permissions, and organization_id from user-controlled update payloads.',
      discovered_by: 'LogicFlawAgent',
      validation_status: 'validated',
      source_verification_status: 'NOT_AVAILABLE',
      source_locations: [],
      evidence: [
        {
          id: 'ev-gb-03',
          evidence_type: 'http_exchange',
          description: 'Privilege escalation confirmed via mass assignment in PATCH /api/v1/users/me',
          request_data: {
            method: 'PATCH',
            url: `${baseUrl}/api/v1/users/me`,
            headers: {
              'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJ1c2VyIn0.sig',
              'Content-Type': 'application/json',
            },
            body: { role: 'admin', permissions: ['manage_users', 'view_billing'] },
          },
          response_data: {
            status_code: 200,
            body_preview: '{"user_id": "user_123", "email": "user@corp.com", "role": "admin", "permissions": ["manage_users", "view_billing"]}',
          },
        },
      ],
      structured_evidence: [],
    },
    {
      id: 'gb-find-04',
      scan_id: '',
      finding_hash: '',
      project_hash: '',
      title: 'Authenticated SSRF via Integration Webhook Endpoint',
      vulnerability_type: 'Server-Side Request Forgery (CWE-918)',
      cwe: 'CWE-918',
      owasp_category: 'A10:2021-Server-Side Request Forgery (SSRF)',
      severity: 'high',
      confidence: 0.95,
      cvss_score: 8.6,
      status: 'CONFIRMED',
      affected_asset: cleanTarget,
      affected_endpoint: `${baseUrl}/api/v1/webhooks/integrations/test`,
      plain_english_summary: 'The webhook testing endpoint accepts custom callback URLs and issues server HTTP POST requests to private cloud metadata services (169.254.169.254) and localhost.',
      business_risk_summary: 'Exfiltration of cloud IAM instance credentials and access to internal VPC microservices.',
      description: 'Backend webhook dispatcher executes outbound HTTP connections to user-specified destinations without private IP validation or DNS pinning.',
      impact: 'Access to cloud instance metadata and internal network services.',
      reproduction_steps: [
        `Send POST ${baseUrl}/api/v1/webhooks/integrations/test with callback_url: "http://169.254.169.254/latest/meta-data/".`,
        'Verify response payload reflects cloud metadata response.',
      ],
      remediation: 'Enforce strict egress proxy rules: resolve DNS hostname before connection and drop any requests resolving to RFC1918 or 169.254.169.254 subnets.',
      discovered_by: 'AuthenticatedAPIAgent',
      validation_status: 'validated',
      source_verification_status: 'NOT_AVAILABLE',
      source_locations: [],
      evidence: [
        {
          id: 'ev-gb-04',
          evidence_type: 'http_exchange',
          description: 'SSRF confirmed against AWS/GCP metadata endpoint',
          request_data: {
            method: 'POST',
            url: `${baseUrl}/api/v1/webhooks/integrations/test`,
            headers: {
              'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.user_token.sig',
              'Content-Type': 'application/json',
            },
            body: { callback_url: 'http://169.254.169.254/computeMetadata/v1/' },
          },
          response_data: {
            status_code: 200,
            body_preview: '{"status": "delivered", "response_status": 200, "response_body": "instance-id\\nservice-accounts/"}',
          },
        },
      ],
      structured_evidence: [],
    },
  ];

  if (isDeep) {
    findings.push({
      id: 'gb-find-05',
      scan_id: '',
      finding_hash: '',
      project_hash: '',
      title: 'Concurrency Race Condition on Promo Code Application API',
      vulnerability_type: 'Race Condition / State Manipulation (CWE-362)',
      cwe: 'CWE-362',
      owasp_category: 'A04:2021-Insecure Design',
      severity: 'medium',
      confidence: 0.91,
      cvss_score: 6.8,
      status: 'CONFIRMED',
      affected_asset: cleanTarget,
      affected_endpoint: `${baseUrl}/api/v1/wallet/promotions/apply`,
      plain_english_summary: 'Submitting 10 concurrent requests with a single-use discount coupon results in the coupon being applied multiple times because database transactions lack pessimistic row locking.',
      business_risk_summary: 'Financial loss through coupon abuse and repeated discount duplication on checkout transactions.',
      description: 'The coupon validation handler reads usage state before updating it without database isolation locks, enabling race-condition multi-use.',
      impact: 'Financial loss through unauthorized balance reduction and repeated promo redemption.',
      reproduction_steps: [
        'Send 10 simultaneous HTTP POST requests to apply single-use code PROMO_100.',
        'Observe multiple successful 200 OK responses with duplicated discount balances.',
      ],
      remediation: 'Use atomic database operations (e.g. UPDATE ... WHERE used = false) or distributed Redis locks during checkout coupon application.',
      discovered_by: 'LogicFlawAgent',
      validation_status: 'validated',
      source_verification_status: 'NOT_AVAILABLE',
      source_locations: [],
      evidence: [
        {
          id: 'ev-gb-05',
          evidence_type: 'http_exchange',
          description: 'Race condition reproduced with 10 concurrent HTTP POST requests',
          request_data: {
            method: 'POST',
            url: `${baseUrl}/api/v1/wallet/promotions/apply`,
            headers: {
              'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.user_token.sig',
              'Content-Type': 'application/json',
            },
            body: { promo_code: 'SAVE100_ONETIME', cart_id: 'cart_8821' },
          },
          response_data: {
            status_code: 200,
            body_preview: '{"status": "applied", "discount_applied": 100.00, "total_applied_count": 4}',
          },
        },
      ],
      structured_evidence: [],
    });
  }

  return {
    technologies: ['REST API (OpenAPI)', 'JSON Web Tokens (JWT)', 'OAuth2 / RBAC', 'Cloud Web Services'],
    endpoints,
    findings,
    verifiedDefenses: [],
    postureStatus: 'vulnerabilities_found',
  };
}
