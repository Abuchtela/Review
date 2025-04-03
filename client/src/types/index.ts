export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface Vulnerability {
  id: string;
  title: string;
  severity: SeverityLevel;
  description: string;
  attackVector: string[];
  affectedContracts: string[];
}

export interface Contract {
  name: string;
  code: string;
}

export interface ExploitScript {
  language: 'javascript' | 'typescript' | 'solidity';
  code: string;
}

export interface VulnerabilityDetail extends Vulnerability {
  vulnerableContract: Contract;
  exploitScript: ExploitScript;
  maliciousContract?: Contract;
  explanation: string;
  recommendations: string[];
  keyPoints: string[];
  securityInsight?: string;
}

export interface TerminalLog {
  content: string;
  type: 'input' | 'output' | 'error' | 'success';
}

export interface CompilationResult {
  success: boolean;
  output: string;
}

export interface ExploitResult {
  success: boolean;
  logs: TerminalLog[];
}
