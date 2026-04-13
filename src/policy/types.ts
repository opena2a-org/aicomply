/**
 * Types for policy pack configuration.
 */

export interface PolicyPackConfig {
  name: string;
  version: string;
  description?: string;
  rules: PolicyRuleConfig[];
}

export interface PolicyRuleConfig {
  id: string;
  name: string;
  description: string;
  patterns: string[];
  action: 'DENY' | 'REDACT' | 'WARN';
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
}
