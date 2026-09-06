export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecurityFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  filePath: string;
  lineNumber: number;
  snippet: string;
  message: string;
  remediation: string;
  entropy?: number;
}

export interface ScanSummary {
  totalFilesScanned: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  elapsedMs: number;
}

export interface ScanResult {
  findings: SecurityFinding[];
  summary: ScanSummary;
}
