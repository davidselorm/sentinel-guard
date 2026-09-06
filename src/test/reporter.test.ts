import { describe, it } from 'node:test';
import assert from 'node:assert';
import { TerminalReporter } from '../reporters/terminal';
import { SarifReporter } from '../reporters/sarif';
import { ScanResult } from '../types';

describe('SentinelGuard Reporters', () => {
  const dummyResult: ScanResult = {
    findings: [
      {
        id: '1',
        ruleId: 'SEC-001',
        ruleName: 'Hardcoded AWS Access Key',
        severity: 'CRITICAL',
        filePath: 'test.ts',
        lineNumber: 10,
        snippet: 'AKIA...TEST',
        message: 'AWS key detected',
        remediation: 'Use env vars',
        entropy: 4.1
      }
    ],
    summary: {
      totalFilesScanned: 1,
      totalFindings: 1,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      elapsedMs: 5
    }
  };

  it('should format clean terminal output', () => {
    const text = TerminalReporter.format(dummyResult);
    assert.ok(text.includes('SENTINEL GUARD SECURITY REPORT'));
    assert.ok(text.includes('CRITICAL'));
  });

  it('should generate valid SARIF v2.1.0 JSON', () => {
    const jsonStr = SarifReporter.generate(dummyResult);
    const parsed = JSON.parse(jsonStr);
    assert.strictEqual(parsed.version, '2.1.0');
    assert.strictEqual(parsed.runs[0].results.length, 1);
  });
});
