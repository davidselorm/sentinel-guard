import { ScanResult } from '../types';

export class SarifReporter {
  public static generate(result: ScanResult): string {
    const sarifDoc = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'SentinelGuard',
              version: '1.0.0',
              informationUri: 'https://github.com/davidselorm/sentinel-guard',
              rules: result.findings.map((f) => ({
                id: f.ruleId,
                name: f.ruleName,
                shortDescription: { text: f.message },
                defaultConfiguration: {
                  level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning'
                }
              }))
            }
          },
          results: result.findings.map((f) => ({
            ruleId: f.ruleId,
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.filePath },
                  region: { startLine: f.lineNumber }
                }
              }
            ]
          }))
        }
      ]
    };

    return JSON.stringify(sarifDoc, null, 2);
  }
}
