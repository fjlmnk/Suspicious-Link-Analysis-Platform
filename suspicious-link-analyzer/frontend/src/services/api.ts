import axios, { type AxiosResponse } from 'axios';
import type {
  User,
  ScanResponse,
  ScanHistoryResponse,
  ThreatReport,
  DemoScenario,
  DemoScanResponse,
  HistoryParams,
  SessionData,
} from '@/types';

const API_BASE = '/api';

function getSessionId(): string {
  let sessionId = localStorage.getItem('session_id');
  if (!sessionId) {
    sessionId = crypto.randomUUID();
    localStorage.setItem('session_id', sessionId);
  }
  return sessionId;
}

const apiClient = axios.create({
  baseURL: API_BASE,
});

apiClient.interceptors.request.use((config) => {
  config.headers['X-Session-Id'] = getSessionId();
  return config;
});

export const api = {
  // Auth
  createSession: (data?: Partial<Omit<SessionData, 'session_id'>>): Promise<AxiosResponse<User>> =>
    apiClient.post<User>('/auth/session', {
      session_id: getSessionId(),
      ...data,
    }),

  getMe: (): Promise<AxiosResponse<User>> =>
    apiClient.get<User>('/users/me'),

  // Scans
  submitScan: (url: string): Promise<AxiosResponse<ScanResponse>> =>
    apiClient.post<ScanResponse>('/scans', { url }),

  getScan: (requestId: number): Promise<AxiosResponse<ScanResponse>> =>
    apiClient.get<ScanResponse>(`/scans/${requestId}`),

  getHistory: (params?: HistoryParams): Promise<AxiosResponse<ScanHistoryResponse>> =>
    apiClient.get<ScanHistoryResponse>('/scans/history', { params }),

  // Reports
  getReport: (reportId: number): Promise<AxiosResponse<ThreatReport>> =>
    apiClient.get<ThreatReport>(`/reports/${reportId}`),

  downloadPdf: (reportId: number): Promise<AxiosResponse<Blob>> =>
    apiClient.get<Blob>(`/reports/${reportId}/pdf`, { responseType: 'blob' }),

  sendToSecurityTeam: (
    reportId: number,
    email?: string
  ): Promise<AxiosResponse<{ success: boolean; message: string }>> =>
    apiClient.post<{ success: boolean; message: string }>(
      `/reports/${reportId}/send-to-security-team`,
      { email }
    ),

  // Demo
  getScenarios: (): Promise<AxiosResponse<DemoScenario[]>> =>
    apiClient.get<DemoScenario[]>('/demo/scenarios'),

  runDemo: (scenarioId: string): Promise<AxiosResponse<DemoScanResponse>> =>
    apiClient.post<DemoScanResponse>('/demo/scans', { scenario_id: scenarioId }),
};

export { getSessionId };
