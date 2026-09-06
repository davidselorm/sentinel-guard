import { ScanResult, SecurityFinding } from '../types';

export class TerminalReporter {
  public static format(result: ScanResult): string {
    const lines: string[] = [];
    lines.push('\n========================================');
    lines.push('  🛡️  SENTINEL GUARD SECURITY REPORT');
    lines.push('========================================\n');

    if (result.findings.length === 0) {
      lines.push('✅ No security vulnerabilities or secret leaks detected.\n');
    } else {
      lines.push(`Found ${result.findings.length} security violation(s):\n`);

      result.findings.forEach((f, idx) => {
        const sevColor = f.severity === 'CRITICAL' ? '🚨 [CRITICAL]' : f.severity === 'HIGH' ? '⚠️  [HIGH]' : 'ℹ️  [' + f.severity + ']';
        lines.push(`${idx + 1}. ${sevColor} ${f.ruleName} (${f.ruleId})`);
        lines.push(`   Location:    ${f.filePath}:${f.lineNumber}`);
        lines.push(`   Violation:   ${f.message}`);
        lines.push(`   Code:        ${f.snippet}`);
        lines.push(`   Remediation: ${f.remediation}\n`);
      });
    }

    lines.push('----------------------------------------');
    lines.push(`Summary:`);
    lines.push(`  Files Scanned: ${result.summary.totalFilesScanned}`);
    lines.push(`  Critical:      ${result.summary.criticalCount}`);
    lines.push(`  High:          ${result.summary.highCount}`);
    lines.push(`  Medium:        ${result.summary.mediumCount}`);
    lines.push(`  Low:           ${result.summary.lowCount}`);
    lines.push(`  Duration:      ${result.summary.elapsedMs}ms`);
    lines.push('========================================\n');

    return lines.join('\n');
  }
}
