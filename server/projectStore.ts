export interface ProjectEntity {
  project_id: string;
  project_name: string;
  target_type: 'url' | 'github_repo' | 'uploaded_code';
  target_location: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectVersionEntity {
  version_id: string;
  project_id: string;
  project_hash: string;
  created_at: string;
  source_files_count: number;
  metadata?: Record<string, any>;
}

export interface ScanEntity {
  scan_id: string;
  project_id: string;
  version_id: string;
  project_hash: string;
  mode: string;
  status: string;
  scan_configuration: Record<string, any>;
  started_at: string;
  completed_at?: string;
}

class MemoryProjectStore {
  private projects: Map<string, ProjectEntity> = new Map();
  private versions: Map<string, ProjectVersionEntity> = new Map();
  private scans: Map<string, ScanEntity> = new Map();

  resolveProjectAndVersion(params: {
    projectName: string;
    targetType: 'url' | 'github_repo' | 'uploaded_code';
    targetLocation: string;
    projectHash: string;
    sourceFilesCount: number;
    metadata?: Record<string, any>;
  }): {
    project: ProjectEntity;
    version: ProjectVersionEntity;
    isNewProject: boolean;
    isNewVersion: boolean;
  } {
    const now = new Date().toISOString();
    const cleanLocation = params.targetLocation.trim();
    const cleanName = params.projectName.trim() || cleanLocation;

    let project: ProjectEntity | undefined;
    for (const p of this.projects.values()) {
      if (
        p.target_location.toLowerCase() === cleanLocation.toLowerCase() ||
        p.project_name.toLowerCase() === cleanName.toLowerCase()
      ) {
        project = p;
        break;
      }
    }

    let isNewProject = false;
    if (!project) {
      isNewProject = true;
      const projectId = `proj-${Math.random().toString(36).substring(2, 10)}`;
      project = {
        project_id: projectId,
        project_name: cleanName,
        target_type: params.targetType,
        target_location: cleanLocation,
        created_at: now,
        updated_at: now,
      };
      this.projects.set(projectId, project);
    } else {
      project.updated_at = now;
      this.projects.set(project.project_id, project);
    }

    let version: ProjectVersionEntity | undefined;
    for (const v of this.versions.values()) {
      if (v.project_id === project.project_id && v.project_hash === params.projectHash) {
        version = v;
        break;
      }
    }

    let isNewVersion = false;
    if (!version) {
      isNewVersion = true;
      const versionId = `ver-${Math.random().toString(36).substring(2, 10)}`;
      version = {
        version_id: versionId,
        project_id: project.project_id,
        project_hash: params.projectHash,
        created_at: now,
        source_files_count: params.sourceFilesCount,
        metadata: params.metadata || {},
      };
      this.versions.set(versionId, version);
    }

    return {
      project,
      version,
      isNewProject,
      isNewVersion,
    };
  }

  recordScan(scan: ScanEntity) {
    this.scans.set(scan.scan_id, scan);
  }

  getScan(scanId: string): ScanEntity | undefined {
    return this.scans.get(scanId);
  }

  getProject(projectId: string): ProjectEntity | undefined {
    return this.projects.get(projectId);
  }

  getVersionsForProject(projectId: string): ProjectVersionEntity[] {
    return Array.from(this.versions.values()).filter((v) => v.project_id === projectId);
  }

  listProjects(): ProjectEntity[] {
    return Array.from(this.projects.values());
  }
}

export const projectStore = new MemoryProjectStore();
