# SentinelGuard 🛡️⚡
> Zero-dependency static code security analyzer, Shannon entropy secret detector, and SAST engine.

![Security Scan](https://img.shields.io/badge/Security-OWASP_Top_10-10b981?style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript_5.5-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![Zero_Dependencies](https://img.shields.io/badge/Dependencies-Zero-blue?style=for-the-badge)

SentinelGuard runs fast, zero-dependency static analysis and entropy detection to intercept leaked API tokens, cryptographic private keys, SQL injections, ReDoS attacks, and arbitrary code executions before code enters git branches.

---

## 🚀 Key Capabilities

- **Shannon Entropy Analysis**: Detect high-randomness credentials and secret tokens with mathematical entropy thresholding ($H = -\sum p_i \log_2 p_i$).
- **OWASP SAST Rules**: Built-in inspection for `eval()`, unparameterized SQL concatenation, ReDoS regular expressions, and committed private keys.
- **Redaction by Default**: All sensitive tokens are safely masked (`AKIA...MPLE`) in log reports and CI artifacts.

---

## ⚡ Usage

```typescript
import { SecurityScanner } from 'sentinel-guard';

const scanner = new SecurityScanner();
const code = `
  const apiKey = "AKIAIOSFODNN7EXAMPLE";
  const result = eval(userInput);
`;

const findings = scanner.scanContent(code, 'src/api.ts');
console.log(scanner.summarize(findings));
```

---

## 📄 License
Apache-2.0 © 2026 [davidselorm](https://github.com/davidselorm)
