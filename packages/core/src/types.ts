export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ModuleStatus = 'completed' | 'failed' | 'skipped' | 'timeout';

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  evidence?: any;
  fix?: {
    title: string;
    description: string;
    code?: string;
    language?: string;
  };
}

export interface ModuleResult {
  module: string;
  status: ModuleStatus;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  data: any;
  findings: Finding[];
  error?: {
    code: string;
    message: string;
  };
}

export interface ScanResult {
  domain: string;
  started_at: string;
  completed_at: string;
  modules: Record<string, ModuleResult>;
  findings: Finding[];
}
