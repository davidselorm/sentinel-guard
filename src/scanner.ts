import { randomUUID } from 'node:crypto';
import { SecurityFinding, ScanResult, Severity } from './types';
import { CORE_RULES, SecurityRule } from './rules/core';
import { EntropyCalculator } from './entropy';

export interface ScannerOptions {
  customRules?: SecurityRule[];
  minSeverity?: Severity;
  minEntropyThreshold?: number;
}

export class SecurityScanner {
  private rules: SecurityRule[];
  private minEntropy: number;

  constructor(options: ScannerOptions = {}) {
    this.rules = [...CORE_RULES, ...(options.customRules || [])];
    this.minEntropy = options.minEntropyThreshold ?? 3.8;
  }

  public scanContent(content: string, filePath: string = 'inline.ts'): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split(/\r?\n/);

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const lineNum = lineIdx + 1;

      for (const rule of this.rules) {
        // Reset regex state for global flags
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = rule.pattern.exec(line)) !== null) {
          const matchedText = match[0];
          const entropy = EntropyCalculator.calculate(matchedText);

          // If rule requires minimum entropy, verify threshold
          if (rule.minEntropy && entropy < rule.minEntropy) {
            continue;
          }

          const maskedSnippet = rule.minEntropy
            ? line.replace(matchedText, EntropyCalculator.maskSecret(matchedText))
            : line.trim();

          findings.push({
            id: randomUUID(),
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            filePath,
            lineNumber: lineNum,
            snippet: maskedSnippet,
            message: rule.message,
            remediation: rule.remediation,
            entropy
          });
        }
      }
    }

    return findings;
  }

  public summarize(findings: SecurityFinding[], totalFiles: number = 1, elapsedMs: number = 0): ScanResult {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    for (const f of findings) {
      if (f.severity === 'CRITICAL') critical++;
      else if (f.severity === 'HIGH') high++;
      else if (f.severity === 'MEDIUM') medium++;
      else if (f.severity === 'LOW') low++;
    }

    return {
      findings,
      summary: {
        totalFilesScanned: totalFiles,
        totalFindings: findings.length,
        criticalCount: critical,
        highCount: high,
        mediumCount: medium,
        lowCount: low,
        elapsedMs
      }
    };
  }
}
