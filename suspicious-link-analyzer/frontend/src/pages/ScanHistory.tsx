import React, { useState, useEffect } from 'react';
import { History, Filter, RefreshCw } from 'lucide-react';
import ScanHistoryTable from '@/components/ScanHistoryTable';
import { api } from '@/services/api';
import type { ScanResponse, ScanStatus, ThreatLevel } from '@/types';

export default function ScanHistory() {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [threatFilter, setThreatFilter] = useState<string>('');

  const fetchHistory = async () => {
    try {
      setLoading(true);
      const res = await api.getHistory({
        page,
        page_size: pageSize,
        status: statusFilter as any || undefined,
        threat_level: threatFilter as any || undefined,
      });
      setScans(res.data.items);
      setTotal(res.data.total);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, statusFilter, threatFilter]);

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="max-w-6xl mx-auto px-4 py-10 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white">Scan History & Audit Trail</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">Review past submitted URLs, provider verdicts, and generated reports.</p>
        </div>

        <button
          onClick={fetchHistory}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-200 text-xs font-semibold self-start transition"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Filter Controls */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center gap-4 text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 font-semibold uppercase">
          <Filter className="w-3.5 h-3.5 text-cyan-400" /> Filters:
        </div>

        <div className="flex items-center gap-2">
          <label className="text-slate-400">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="PENDING">PENDING</option>
            <option value="FAILED">FAILED</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-slate-400">Threat Level:</label>
          <select
            value={threatFilter}
            onChange={(e) => { setThreatFilter(e.target.value); setPage(1); }}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Threat Levels</option>
            <option value="SAFE">SAFE</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="DANGEROUS">DANGEROUS</option>
          </select>
        </div>

        {(statusFilter || threatFilter) && (
          <button
            onClick={() => { setStatusFilter(''); setThreatFilter(''); setPage(1); }}
            className="text-xs text-rose-400 hover:underline ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Table */}
      <ScanHistoryTable
        scans={scans}
        page={page}
        totalPages={totalPages}
        onPageChange={setPage}
        isLoading={loading}
      />
    </div>
  );
}
