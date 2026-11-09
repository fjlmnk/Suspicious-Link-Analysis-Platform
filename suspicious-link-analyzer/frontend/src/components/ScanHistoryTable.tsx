import React from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, ShieldAlert, FileText } from 'lucide-react';
import ThreatBadge from '@/components/ThreatBadge';
import type { ScanResponse } from '@/types';

interface ScanHistoryTableProps {
  scans: ScanResponse[];
  onPageChange?: (newPage: number) => void;
  page?: number;
  totalPages?: number;
  isLoading?: boolean;
}

export default function ScanHistoryTable({
  scans,
  onPageChange,
  page = 1,
  totalPages = 1,
  isLoading = false,
}: ScanHistoryTableProps) {
  if (isLoading) {
    return (
      <div className="w-full bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 animate-pulse">
        Loading scan records...
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="w-full bg-slate-900/60 border border-slate-800 rounded-xl p-10 text-center">
        <ShieldAlert className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 className="text-base font-semibold text-slate-300">No scans found</h3>
        <p className="text-sm text-slate-500 mt-1">Submit a URL on the dashboard or run a demo scenario to see history.</p>
      </div>
    );
  }

  return (
    <div className="w-full overflow-hidden border border-slate-800 rounded-xl bg-slate-900/80 shadow-lg">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/60 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-3.5 px-4 font-semibold">Analyzed URL</th>
              <th className="py-3.5 px-4 font-semibold">Date & Time</th>
              <th className="py-3.5 px-4 font-semibold">Status</th>
              <th className="py-3.5 px-4 font-semibold">Verdict</th>
              <th className="py-3.5 px-4 font-semibold">Risk Score</th>
              <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 font-mono text-xs">
            {scans.map((scan) => {
              const threatLevel = scan.threat_report?.threat_level;
              const riskScore = scan.threat_report?.risk_score;
              const dateStr = new Date(scan.submitted_at).toLocaleString();

              return (
                <tr key={scan.id} className="hover:bg-slate-800/50 transition-colors">
                  <td className="py-3.5 px-4 max-w-xs truncate text-cyan-400 font-sans" title={scan.url}>
                    {scan.is_demo && (
                      <span className="mr-2 px-1.5 py-0.5 rounded text-[10px] bg-indigo-900/80 text-indigo-300 border border-indigo-700">
                        DEMO
                      </span>
                    )}
                    {scan.url}
                  </td>
                  <td className="py-3.5 px-4 text-slate-400 font-sans">{dateStr}</td>
                  <td className="py-3.5 px-4 font-sans">
                    <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${
                      scan.status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      scan.status === 'PENDING' ? 'bg-amber-950 text-amber-400 border border-amber-800 animate-pulse' :
                      'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-sans">
                    {threatLevel ? (
                      <ThreatBadge level={threatLevel} />
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 font-sans font-medium">
                    {riskScore !== undefined ? (
                      <span className={
                        riskScore >= 70 ? 'text-rose-400 font-bold' :
                        riskScore >= 30 ? 'text-amber-400' :
                        'text-emerald-400'
                      }>
                        {riskScore} / 100
                      </span>
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right space-x-2 font-sans">
                    <Link
                      to={`/scan/${scan.id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition"
                    >
                      <ExternalLink className="w-3 h-3" />
                      View
                    </Link>
                    {scan.threat_report && (
                      <Link
                        to={`/report/${scan.threat_report.id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800/60 hover:bg-cyan-900/60 text-cyan-300 text-xs transition"
                      >
                        <FileText className="w-3 h-3" />
                        Report
                      </Link>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && onPageChange && (
        <div className="flex items-center justify-between px-4 py-3 bg-slate-950/40 border-t border-slate-800 text-sm">
          <span className="text-slate-400 text-xs">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => onPageChange(page - 1)}
              className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 text-xs"
            >
              Previous
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => onPageChange(page + 1)}
              className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 text-xs"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
