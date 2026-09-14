import crypto from 'crypto';

export interface FindingFingerprintInput {
  project_hash?: string;
  vulnerability_type: string;
  file?: string;
  endpoint?: string;
  parameter?: string;
  sink?: string;
  cwe?: string;
}

export function computeFindingHash(input: FindingFingerprintInput): string {
  const normProjectHash = (input?.project_hash || 'global_project').trim().toLowerCase();
  const normVulnType = (input?.vulnerability_type || 'VULNERABILITY').trim().toUpperCase().replace(/\s+/g, '_');
  const normFile = (input?.file || '').trim().replace(/\\/g, '/').toLowerCase();
  const normEndpoint = (input?.endpoint || '').trim().replace(/\/$/, '').toLowerCase();
  const normParam = (input?.parameter || '').trim().toLowerCase();
  const normSink = (input?.sink || '').trim().toLowerCase();
  const normCwe = (input?.cwe || '').trim().toUpperCase();

  const canonicalString = [
    `PROJECT:${normProjectHash}`,
    `TYPE:${normVulnType}`,
    `CWE:${normCwe}`,
    `FILE:${normFile}`,
    `ENDPOINT:${normEndpoint}`,
    `PARAM:${normParam}`,
    `SINK:${normSink}`,
  ].join('|');

  return crypto.createHash('sha256').update(canonicalString).digest('hex');
}
