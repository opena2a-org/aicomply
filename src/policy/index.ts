/**
 * Policy pack loader.
 *
 * Loads YAML-based policy packs that define compliance rules
 * for different regulatory contexts (HIPAA, PCI-DSS, etc.).
 *
 * STUB: V1 uses built-in default policy. YAML loading in V2.
 */

import type { PolicyPack } from '../types';
import type { PolicyPackConfig } from './types';

const DEFAULT_POLICY: PolicyPack = {
  name: 'default',
  version: '1.0.0',
  rules: [
    {
      id: 'pii-ssn',
      name: 'Social Security Number',
      description: 'Detects US Social Security Numbers',
      patterns: ['SSN'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'pii-pan',
      name: 'Payment Card Number',
      description: 'Detects payment card numbers (PCI-DSS)',
      patterns: ['PAN'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'credential-leak',
      name: 'Credential Exposure',
      description: 'Detects exposed API keys and tokens',
      patterns: ['CREDENTIAL'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'cui-marking',
      name: 'CUI Marking',
      description: 'Detects Controlled Unclassified Information markings',
      patterns: ['CUI'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'financial-iban',
      name: 'IBAN',
      description: 'Detects International Bank Account Numbers',
      patterns: ['IBAN'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'healthcare-mrn',
      name: 'Medical Record Number',
      description: 'Detects medical record numbers (HIPAA)',
      patterns: ['MRN'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'healthcare-npi',
      name: 'National Provider Identifier',
      description: 'Detects NPI numbers',
      patterns: ['NPI'],
      action: 'WARN',
      severity: 'medium',
    },
  ],
};

/**
 * Load a policy pack by name.
 * V1: always returns the default built-in policy.
 * V2: will load from YAML files.
 */
export function loadPolicyPack(_name?: string): PolicyPack {
  // V2: load from YAML file, validate against schema
  return DEFAULT_POLICY;
}

/**
 * Validate a policy pack configuration.
 */
export function validatePolicyConfig(config: PolicyPackConfig): string[] {
  const errors: string[] = [];

  if (!config.name) errors.push('Policy pack name is required');
  if (!config.version) errors.push('Policy pack version is required');
  if (!config.rules || config.rules.length === 0) {
    errors.push('Policy pack must have at least one rule');
  }

  for (const rule of config.rules ?? []) {
    if (!rule.id) errors.push(`Rule missing id`);
    if (!rule.action) errors.push(`Rule ${rule.id}: missing action`);
    if (!['DENY', 'REDACT', 'WARN'].includes(rule.action)) {
      errors.push(`Rule ${rule.id}: invalid action '${rule.action}'`);
    }
  }

  return errors;
}
