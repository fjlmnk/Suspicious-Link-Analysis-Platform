import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ShieldAlert,
  Loader2,
  FileDown,
  Send,
  ArrowLeft,
  CheckCircle2,
  AlertOctagon,
  Clock,
  Sparkles,
} from 'lucide-react';
import { api } from '@/services/api';
import { useUser } from '@/services/userContext';
import ThreatBadge from '@/components/ThreatBadge';
import RiskScoreGauge from '@/components/RiskScoreGauge';
import ProviderResultCard from '@/components/ProviderResultCard';
import type { ScanResponse } from '@/types';

export default function ScanResult() {
  const { id } = useParams<{ id: string }>();
  const { isEmployee } = useUser();
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sendingSecurity, setSendingSecurity] = useState(false);
  const [securityNotice, setSecurityNotice] = useState<string | null>(null);

  const fetchScan = async () => {
    if (!id) return;
    try {
      const res = await api.getScan(parseInt(id, 10));
      setScan(res.data);
      return res.data;
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to retrieve scan result');
      return null;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let interval: any = null;

    const run = async () => {
      const initial = await fetchScan();
      if (initial && initial.status === 'PENDING') {
        interval = setInterval(async () => {
          const updated = await fetchScan();
          if (updated && updated.status !== 'PENDING') {
            clearInterval(interval);
          }
        }, 2000);
      }
    };

    run();

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [id]);

  const handleDownloadPdf = async () => {
    if (!scan?.threat_report) return;
    try {
      const res = await api.downloadPdf(scan.threat_report.id);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat_report_${scan.threat_report.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download PDF report');
    }
  };

  const handleSendToSecurity = async () => {
    if (!scan?.threat_report) return;
    try {
      setSendingSecurity(true);
      const res = await api.sendToSecurityTeam(scan.threat_report.id);
      setSecurityNotice(res.data.message);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Error communicating with security team');
    } finally {
      setSendingSecurity(false);
    }
  };

  if (loading && !scan) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-20 text-center space-y-4">
        <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mx-auto" />
        <h2 className="text-xl font-bold text-slate-200">Initializing Security Analysis...</h2>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center space-y-4">
        <AlertOctagon className="w-12 h-12 text-rose-500 mx-auto" />
        <h2 className="text-2xl font-bold text-white">Scan Error</h2>
        <p className="text-slate-400">{error || 'Requested scan could not be found'}</p>
        <Link
          to="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-sm hover:bg-slate-700"
        >
          <ArrowLeft className="w-4 h-4" /> Return to Dashboard
        </Link>
      </div>
    );
  }

  const report = scan.threat_report;

  return (
    <div className="max-w-5xl mx-auto px-4 py-10 space-y-8">
      {/* Top Bar Navigation */}
      <div className="flex items-center justify-between">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        {scan.is_demo && (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" /> Demo Simulation
          </span>
        )}
      </div>

      {/* Target URL Header */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-2">
        <span className="text-xs uppercase font-semibold text-slate-500 tracking-wider">Target URL Under Inspection</span>
        <div className="text-lg sm:text-xl font-mono text-cyan-400 break-all">{scan.url}</div>
        <div className="flex items-center gap-4 text-xs text-slate-400 pt-2 border-t border-slate-800/80">
          <span>Scan ID: #{scan.id}</span>
          <span>&bull;</span>
          <span>Submitted: {new Date(scan.submitted_at).toLocaleString()}</span>
        </div>
      </div>

      {/* Scan in Progress */}
      {scan.status === 'PENDING' && (
        <div className="p-10 rounded-2xl bg-slate-900/80 border border-cyan-900/50 text-center space-y-4">
          <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mx-auto" />
          <h3 className="text-xl font-bold text-white">Aggregating Threat Feeds...</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Contacting VirusTotal, Google Safe Browsing, and running structural heuristics. Results will update automatically.
          </p>
        </div>
      )}

      {/* Scan Failed */}
      {scan.status === 'FAILED' && (
        <div className="p-8 rounded-2xl bg-rose-950/40 border border-rose-800 text-center space-y-3">
          <AlertOctagon className="w-10 h-10 text-rose-500 mx-auto" />
          <h3 className="text-lg font-bold text-white">Analysis Failed</h3>
          <p className="text-sm text-slate-300 max-w-md mx-auto">
            The target URL could not be resolved or was rejected due to SSRF / policy restrictions.
          </p>
        </div>
      )}

      {/* Scan Completed with Report */}
      {scan.status === 'COMPLETED' && report && (
        <>
          {/* Verdict Overview Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 rounded-2xl bg-slate-900 border border-slate-800 items-center">
            <div className="md:col-span-2 space-y-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Aggregated Security Classification</span>
              <div className="flex items-center gap-4">
                <ThreatBadge level={report.threat_level} size="lg" />
                <span className="text-slate-400 text-sm">
                  {report.threat_level === 'SAFE' && 'Clean reputation across all queried threat feeds.'}
                  {report.threat_level === 'SUSPICIOUS' && 'Caution recommended due to ambiguous or suspicious indicators.'}
                  {report.threat_level === 'DANGEROUS' && 'Immediate danger: Known malicious attack vector detected.'}
                </span>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-3 pt-3">
                <button
                  onClick={handleDownloadPdf}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold shadow-md transition"
                >
                  <FileDown className="w-4 h-4" /> Download PDF Report
                </button>

                {isEmployee && (
                  <button
                    onClick={handleSendToSecurity}
                    disabled={sendingSecurity}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold shadow-md transition disabled:opacity-50"
                  >
                    <Send className="w-4 h-4" />
                    {sendingSecurity ? 'Transmitting...' : 'Send to Security Team'}
                  </button>
                )}
              </div>

              {securityNotice && (
                <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs">
                  {securityNotice}
                </div>
              )}
            </div>

            <div className="flex flex-col items-center justify-center p-4 border-t md:border-t-0 md:border-l border-slate-800">
              <RiskScoreGauge score={report.risk_score} />
            </div>
          </div>

          {/* Provider Verdicts */}
          <div className="space-y-4">
            <h3 className="text-lg font-bold text-slate-100">Threat Provider Telemetry</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {report.provider_verdicts?.map((pv) => (
                <ProviderResultCard key={pv.id || pv.provider_name} verdict={pv} />
              ))}
            </div>
          </div>

          {/* Explanation Box */}
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <h3 className="text-lg font-bold text-slate-100">Comprehensive Threat Assessment</h3>
            <div className="text-sm text-slate-300 whitespace-pre-line leading-relaxed font-sans bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
              {report.explanation}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
