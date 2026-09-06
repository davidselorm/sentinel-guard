import { Severity } from '../types';

export interface SecurityRule {
  id: string;
  name: string;
  severity: Severity;
  pattern: RegExp;
  minEntropy?: number;
  message: string;
  remediation: string;
}

export const CORE_RULES: SecurityRule[] = [
  {
    id: 'SEC-001',
    name: 'Hardcoded AWS Access Key',
    severity: 'CRITICAL',
    pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    minEntropy: 3.5,
    message: 'Hardcoded AWS Access Key ID detected in source code.',
    remediation: 'Remove the credential and use AWS IAM Roles or environment variables.'
  },
  {
    id: 'SEC-002',
    name: 'Exposed GitHub Personal Access Token',
    severity: 'CRITICAL',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    minEntropy: 4.0,
    message: 'Hardcoded GitHub Personal Access Token or OAuth Secret detected.',
    remediation: 'Revoke the token immediately in GitHub Settings and load via Secrets Manager.'
  },
  {
    id: 'SEC-003',
    name: 'Embedded RSA/EC Private Key',
    severity: 'CRITICAL',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    message: 'Cryptographic private key block committed directly in source code.',
    remediation: 'Store private keys in a secure key management service (KMS) or Vault.'
  },
  {
    id: 'SEC-004',
    name: 'Dangerous eval() Execution',
    severity: 'HIGH',
    pattern: /\beval\s*\([^\)]*\)/g,
    message: 'Use of eval() facilitates arbitrary remote code execution (RCE) vulnerabilities.',
    remediation: 'Refactor away from eval() using safe JSON parsing or explicit dispatch tables.'
  },
  {
    id: 'SEC-005',
    name: 'Unparameterized Raw SQL Query Concatenation',
    severity: 'HIGH',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[a-zA-Z0-9_\$]+/gi,
    message: 'Dynamic SQL string concatenation may introduce SQL Injection vulnerabilities.',
    remediation: 'Use parameterized queries, prepared statements, or an ORM query builder.'
  },
  {
    id: 'SEC-006',
    name: 'Exponential ReDoS Vulnerability Pattern',
    severity: 'MEDIUM',
    pattern: /\/([a-zA-Z0-9_]+[\*\+]\??){2,}\//g,
    message: 'Nested quantifiers detected in regular expression, susceptible to ReDoS denial of service.',
    remediation: 'Simplify regex quantifier structure and avoid nested repetition operators.'
  }
];
