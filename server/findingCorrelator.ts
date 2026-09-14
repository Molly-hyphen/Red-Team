import { computeFindingHash } from './findingFingerprint.js';

export class ServerFindingCorrelator {
  correlate(findings: any[]): any[] {
    if (!findings || findings.length === 0) return [];

    const grouped: any[] = [];

    for (const f of findings) {
      if (!f.finding_hash) {
        f.finding_hash = computeFindingHash({
          project_hash: f.project_hash,
          vulnerability_type: f.vulnerability_type,
          file: f.file || f.affected_asset,
          endpoint: f.endpoint || f.affected_endpoint,
          parameter: f.parameter,
          cwe: f.cwe,
        });
      }

      let match = grouped.find((g) => this.isMatch(g, f));
      if (match) {
        // Merge without over-merging
        const existingEvIds = new Set((match.structured_evidence || []).map((e: any) => e.id));
        const newEv = (f.structured_evidence || []).filter((e: any) => !existingEvIds.has(e.id));
        match.structured_evidence = [...(match.structured_evidence || []), ...newEv];

        // Merge standard evidence array
        const existingLegacyEvIds = new Set((match.evidence || []).map((e: any) => e.id || e.description));
        const newLegacyEv = (f.evidence || []).filter((e: any) => !existingLegacyEvIds.has(e.id || e.description));
        match.evidence = [...(match.evidence || []), ...newLegacyEv];
        
        if (!match.correlated_agents) match.correlated_agents = [match.discovered_by];
        if (f.discovered_by && !match.correlated_agents.includes(f.discovered_by)) {
          match.correlated_agents.push(f.discovered_by);
        }
        match.merged_sources_count = (match.merged_sources_count || 1) + 1;

        if (f.status === 'CONFIRMED') {
          match.status = 'CONFIRMED';
          match.validation_status = 'validated';
        }
      } else {
        grouped.push({
          ...f,
          correlated_agents: [f.discovered_by],
          merged_sources_count: 1,
          evidence: [...(f.evidence || [])],
          structured_evidence: [...(f.structured_evidence || [])],
        });
      }
    }

    return grouped;
  }

  private isMatch(a: any, b: any): boolean {
    if (a.finding_hash && b.finding_hash && a.finding_hash === b.finding_hash) return true;
    const locA = (a.endpoint || a.affected_endpoint || a.file || '').trim().toLowerCase();
    const locB = (b.endpoint || b.affected_endpoint || b.file || '').trim().toLowerCase();
    if (!locA || locA !== locB) return false;

    const paramA = (a.parameter || '').trim().toLowerCase();
    const paramB = (b.parameter || '').trim().toLowerCase();
    if (paramA && paramB && paramA !== paramB) return false;

    return a.vulnerability_type?.toLowerCase() === b.vulnerability_type?.toLowerCase() || a.cwe === b.cwe;
  }
}

export const serverFindingCorrelator = new ServerFindingCorrelator();
