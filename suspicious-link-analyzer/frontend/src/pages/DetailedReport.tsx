import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileText,
  FileDown,
  Send,
  ArrowLeft,
  Calendar,
  Layers,
  AlertTriangle,
  Loader2,
  CheckCircle,
} from 'lucide-react';
import { api } from '@/services/api';
import { useUser } from '@/services/userContext';
import ThreatBadge from '@/components/ThreatBadge';
import RiskScoreGauge from '@/components/RiskScoreGauge';
import ProviderResultCard from '@/components/ProviderResultCard';
import type { ThreatReport } from '@/types';

export default function DetailedReport() {
  const { id } = useParams<{ id: string }>();
  const { isEmployee } = useUser();
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [securityMessage, setSecurityMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchReport = async () => {
      if (!id) return;
      try {
        setLoading(true);
        const res = await api.getReport(parseInt(id, 10));
        setReport(res.data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || 'Failed to fetch threat report');
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [id]);

  const handleDownloadPdf = async () => {
    if (!report) return;
    try {
      const res = await api.downloadPdf(report.id);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat_report_${report.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download PDF');
    }
  };

  const handleSendToSecurity = async () => {
    if (!report) return;
    try {
      setIsSending(true);
      const res = await api.sendToSecurityTeam(report.id);
      setSecurityMessage(res.data.message);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to notify security team');
    } finally {
      setIsSending(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-20 text-center space-y-3">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
        <p className="text-slate-400 text-sm">Loading detailed security report...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-rose-500 mx-auto" />
        <h2 className="text-2xl font-bold text-white">Report Unavailable</h2>
        <p className="text-slate-400">{error || 'Could not locate report'}</p>
        <Link
          to="/history"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-sm hover:bg-slate-700"
        >
          <ArrowLeft className="w-4 h-4" /> Return to History
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-10 space-y-8">
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <Link
          to="/history"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition"
        >
          <ArrowLeft className="w-4 h-4" /> Back to History
        </Link>
        <span className="text-xs text-slate-500 font-mono">Report #{report.id}</span>
      </div>

      {/* Main Report Card */}
      <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold uppercase text-cyan-400 tracking-wider">
              <FileText className="w-4 h-4" /> Threat Intelligence Audit
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">Official Threat Report</h1>
            <div className="flex items-center gap-4 text-xs text-slate-400 mt-2 font-mono">
              <span className="flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5" />
                {new Date(report.generated_at).toUTCString()}
              </span>
              <span>&bull;</span>
              <span>Request #{report.request_id}</span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleDownloadPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold transition shadow-md"
            >
              <FileDown className="w-4 h-4" /> Export as PDF
            </button>
            {isEmployee && (
              <button
                onClick={handleSendToSecurity}
                disabled={isSending}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold transition shadow-md disabled:opacity-50"
              >
                <Send className="w-4 h-4" />
                {isSending ? 'Sending...' : 'Notify Security Team'}
              </button>
            )}
          </div>
        </div>

        {securityMessage && (
          <div className="p-4 rounded-xl bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-sm flex items-center gap-2">
            <CheckCircle className="w-4 h-4 shrink-0" />
            <span>{securityMessage}</span>
          </div>
        )}

        {/* Threat Level & Score Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          <div className="md:col-span-2 space-y-3">
            <h3 className="text-xs font-semibold uppercase text-slate-500 tracking-wider">Overall Verdict</h3>
            <div className="flex items-center gap-4">
              <ThreatBadge level={report.threat_level} size="lg" />
              <span className="text-slate-300 text-sm font-medium">
                {report.threat_level === 'SAFE' && 'Low risk indicator. Verified clean by threat data providers.'}
                {report.threat_level === 'SUSPICIOUS' && 'Caution warranted. Conflicting signals or anomalous patterns.'}
                {report.threat_level === 'DANGEROUS' && 'Confirmed malicious URL. Do not navigate or expose credentials.'}
              </span>
            </div>
          </div>
          <div className="flex flex-col items-center justify-center p-4">
            <RiskScoreGauge score={report.risk_score} />
          </div>
        </div>

        {/* Provider Breakdown */}
        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Provider Feed Verdicts ({report.provider_verdicts?.length || 0})
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {report.provider_verdicts?.map((pv) => (
              <ProviderResultCard key={pv.id} verdict={pv} />
            ))}
          </div>
        </div>

        {/* Explanation Details */}
        <div className="space-y-3 pt-4 border-t border-slate-800">
          <h3 className="text-base font-bold text-slate-100">Findings & Recommendations</h3>
          <div className="p-5 rounded-xl bg-slate-950 text-slate-300 text-sm leading-relaxed whitespace-pre-line border border-slate-800 font-sans">
            {report.explanation}
          </div>
        </div>
      </div>
    </div>
  );
}
