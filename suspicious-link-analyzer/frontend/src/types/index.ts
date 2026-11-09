// ========== Enums ==========

export enum ScanStatus {
  PENDING = 'PENDING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

export enum ThreatLevel {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  DANGEROUS = 'DANGEROUS',
}

export enum UserRole {
  REGULAR = 'REGULAR',
  COMPANY_EMPLOYEE = 'COMPANY_EMPLOYEE',
}

// ========== Interfaces ==========

export interface User {
  id: number;
  session_id: string;
  created_at: string;
  role: UserRole;
  company_name?: string;
  department?: string;
}

export interface ProviderVerdict {
  id: number;
  provider_name: string;
  is_malicious: boolean;
  detection_count: number;
  category: string;
  checked_at: string;
  provider_status: string;
}

export interface ThreatReport {
  id: number;
  request_id: number;
  threat_level: ThreatLevel;
  risk_score: number;
  explanation: string;
  generated_at: string;
  provider_verdicts: ProviderVerdict[];
}

export interface ScanResponse {
  id: number;
  url: string;
  submitted_at: string;
  status: ScanStatus;
  is_demo: boolean;
  user_id: number;
  threat_report?: ThreatReport;
}

export interface ScanHistoryResponse {
  items: ScanResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface DemoScenario {
  id: string;
  name: string;
  url: string;
  description: string;
  expected_threat_level: string;
}

export interface DemoScanResponse extends ScanResponse {}

// ========== API Params ==========

export interface HistoryParams {
  page?: number;
  page_size?: number;
  status?: ScanStatus | '';
  threat_level?: ThreatLevel | '';
  date_from?: string;
  date_to?: string;
}

export interface SessionData {
  session_id: string;
  role?: UserRole;
  company_name?: string;
  department?: string;
}
