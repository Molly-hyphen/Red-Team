export interface ServerStructuredEvidence {
  id: string;
  finding_id?: string;
  hypothesis_id?: string;
  observation_ids?: string[];
  evidence_type: 'source_ast' | 'taint_flow' | 'http_exchange' | 'config_sink' | 'poc_execution' | 'auth_bypass';
  description: string;
  file?: string;
  line_number_start?: number;
  line_number_end?: number;
  line_number?: number;
  function_name?: string;
  class_name?: string;
  endpoint?: string;
  parameter?: string;
  input_source?: string;
  data_flow?: string[];
  sink?: string;
  http_request?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: any;
  };
  http_response?: {
    status_code: number;
    headers?: Record<string, string>;
    body_preview?: string;
    latency_ms?: number;
  };
  configuration?: Record<string, any>;
  dependency?: {
    name: string;
    version: string;
    known_advisory?: string;
  };
  auth_state?: {
    caller_role?: string;
    target_resource_owner?: string;
    token_present?: boolean;
    header_used?: string;
  };
  safe_validation_result?: {
    passed: boolean;
    reproduced: boolean;
    execution_time_ms?: number;
    payload_applied?: string;
    notes?: string;
  };
  reproducible_behavior?: string;
  raw_payload?: string;
  created_at: string;
}

export class ServerEvidenceCollector {
  private registry: Map<string, ServerStructuredEvidence> = new Map();

  collect(params: Partial<ServerStructuredEvidence>): ServerStructuredEvidence {
    const id = params.id || `ev-${Math.random().toString(36).substring(2, 10)}`;
    const evidence: ServerStructuredEvidence = {
      id,
      evidence_type: params.evidence_type || 'source_ast',
      description: params.description || '',
      created_at: new Date().toISOString(),
      ...params,
    };
    this.registry.set(id, evidence);
    return evidence;
  }

  get(id: string) {
    return this.registry.get(id);
  }

  clear() {
    this.registry.clear();
  }
}

export const serverEvidenceCollector = new ServerEvidenceCollector();
