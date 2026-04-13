# @opena2a/aicomply

Dual-layer compliance classifier for AI agent communications.

## Overview

AIComply provides real-time content classification to detect sensitive data (PII, credentials, controlled markings) in AI agent message flows. It uses a dual-layer architecture: deterministic regex patterns for V1, with a NanoMind-Guard neural classifier planned for V2.

## Installation

```bash
npm install @opena2a/aicomply
```

## Usage

```typescript
import { comply } from '@opena2a/aicomply';

const result = await comply({
  content: 'Send payment to card 4111-1111-1111-1111',
});

console.log(result.verdict); // 'VIOLATION'
console.log(result.violations); // [{ type: 'PAN', ... }]
```

## Architecture

- **Regex Classifier** -- Deterministic pattern matching for SSN, PAN (Luhn-validated), CUI markings, credentials (AWS keys, GitHub tokens, Bearer tokens), IBAN, passport numbers, MRN, and NPI.
- **Guard Client** -- IPC client for NanoMind-Guard neural classifier (V2, currently stubbed).
- **Dual-Layer Merge** -- Both classifiers must return CLEAN for content to pass. Either flagging triggers a VIOLATION.
- **Session Vault** -- In-memory AES-256-GCM encrypted storage for sensitive content during processing.
- **Policy Packs** -- YAML-based policy configuration for compliance rule sets.
- **ARP Client** -- Agent Reputation Protocol integration for behavioral risk signals.

## License

UNLICENSED -- Private package.
