import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecurityScanner } from '../scanner';
import { EntropyCalculator } from '../entropy';

describe('SentinelGuard Security Scanner', () => {
  it('should accurately compute Shannon entropy', () => {
    const lowEntropy = EntropyCalculator.calculate('aaaaaaa');
    const highEntropy = EntropyCalculator.calculate('A3T4K8P1Q9X2Z7M0B5V');
    assert.strictEqual(lowEntropy, 0);
    assert.ok(highEntropy > 3.5);
  });

  it('should detect committed AWS secret tokens with high entropy', () => {
    const scanner = new SecurityScanner();
    const code = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";';
    const findings = scanner.scanContent(code, 'config/aws.ts');

    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].ruleId, 'SEC-001');
    assert.strictEqual(findings[0].severity, 'CRITICAL');
  });

  it('should flag dangerous eval() execution', () => {
    const scanner = new SecurityScanner();
    const code = 'const result = eval(userInput);';
    const findings = scanner.scanContent(code, 'src/executor.ts');

    assert.ok(findings.some((f) => f.ruleId === 'SEC-004'));
  });
});
