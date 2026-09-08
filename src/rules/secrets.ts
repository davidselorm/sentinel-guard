export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  minEntropy?: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export const KNOWN_SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
    severity: 'CRITICAL'
  },
  {
    id: 'GITHUB_PAT',
    name: 'GitHub Personal Access Token',
    regex: /\bghp_[a-zA-Z0-9]{36}\b/,
    severity: 'CRITICAL'
  },
  {
    id: 'GENERIC_PRIVATE_KEY',
    name: 'Asymmetric Private Key Header',
    regex: /-----BEGIN (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----/,
    severity: 'CRITICAL'
  },
  {
    id: 'SLACK_TOKEN',
    name: 'Slack OAuth Bot/User Token',
    regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/,
    severity: 'HIGH'
  }
];

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freqs: Record<string, number> = {};
  for (const char of str) {
    freqs[char] = (freqs[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freqs) {
    const p = freqs[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface ScanFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  matchedText: string;
  line: number;
  entropy?: number;
}

export function scanSourceForSecrets(source: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = source.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    for (const rule of KNOWN_SECRET_PATTERNS) {
      const match = rule.regex.exec(line);
      if (match) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          matchedText: match[0],
          line: lineNum + 1,
          entropy: calculateShannonEntropy(match[0])
        });
      }
    }
  }

  return findings;
}
