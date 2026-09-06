#!/usr/bin/env node
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { SecurityScanner } from './scanner';
import { TerminalReporter } from './reporters/terminal';
import { SarifReporter } from './reporters/sarif';

const args = process.argv.slice(2);
const targetFile = args[0];
const sarifFlag = args.includes('--sarif');

if (!targetFile) {
  console.log('Usage: sentinel-guard <file-path> [--sarif]');
  process.exit(1);
}

const fullPath = resolve(process.cwd(), targetFile);
if (!existsSync(fullPath)) {
  console.error(`Error: File not found at ${fullPath}`);
  process.exit(1);
}

const content = readFileSync(fullPath, 'utf8');
const startTime = Date.now();
const scanner = new SecurityScanner();
const findings = scanner.scanContent(content, targetFile);
const duration = Date.now() - startTime;
const result = scanner.summarize(findings, 1, duration);

if (sarifFlag) {
  console.log(SarifReporter.generate(result));
} else {
  console.log(TerminalReporter.format(result));
}

if (result.summary.criticalCount > 0 || result.summary.highCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
