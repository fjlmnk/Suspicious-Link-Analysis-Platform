import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Activity, Lock, Database, ArrowRight, Zap, AlertTriangle } from 'lucide-react';
import URLInput from '@/components/URLInput';
import ScanHistoryTable from '@/components/ScanHistoryTable';
import { api } from '@/services/api';
import type { ScanResponse } from '@/types';

export default function Dashboard() {
  const navigate = useNavigate();
  const [recentScans, setRecentScans] = useState<ScanResponse[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);

  const fetchRecentScans = async () => {
    try {
      setIsLoadingHistory(true);
      const res = await api.getHistory({ page: 1, page_size: 5 });
      setRecentScans(res.data.items);
    } catch (err) {
      console.error('Failed to load recent scans:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchRecentScans();
  }, []);

  const handleScanSubmitted = (scanId: number) => {
    navigate(`/scan/${scanId}`);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-10 space-y-12">
      {/* Hero Section */}
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-400 text-xs font-semibold tracking-wide uppercase">
          <Shield className="w-3.5 h-3.5" />
          Real-Time Threat Intelligence Engine
        </div>
        <h1 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
          Analyze URLs for <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-sky-400">Phishing & Malware</span>
        </h1>
        <p className="text-slate-400 text-base sm:text-lg">
          Protect yourself and your organization before clicking. Aggregating multi-vendor threat detection from VirusTotal, Google Safe Browsing, and structural heuristic engines.
        </p>
      </div>

      {/* Main Input Card */}
      <div className="max-w-3xl mx-auto">
        <URLInput onScanSuccess={handleScanSubmitted} />
      </div>

      {/* Feature Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm space-y-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <Database className="w-5 h-5" />
          </div>
          <h3 className="text-lg font-bold text-slate-100">Multi-Vendor Intelligence</h3>
          <p className="text-sm text-slate-400 leading-relaxed">
            Simultaneously queries VirusTotal antivirus engines and Google Safe Browsing telemetry with automatic normalization.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm space-y-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400">
            <Lock className="w-5 h-5" />
          </div>
          <h3 className="text-lg font-bold text-slate-100">Zero-Fetch SSRF Protection</h3>
          <p className="text-sm text-slate-400 leading-relaxed">
            Strict client and server isolation prevents Server-Side Request Forgery, loopback spoofing, and internal network exposure.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm space-y-3">
          <div className="w-10 h-10 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400">
            <Zap className="w-5 h-5" />
          </div>
          <h3 className="text-lg font-bold text-slate-100">Interactive Demo Scenarios</h3>
          <p className="text-sm text-slate-400 leading-relaxed">
            Test realistic safe, suspicious, and dangerous threat payloads instantly without requiring third-party API credentials.
          </p>
          <Link
            to="/demo"
            className="inline-flex items-center gap-1 text-xs font-semibold text-purple-400 hover:text-purple-300"
          >
            Explore Demo Scenarios <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* Recent Scans Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xl font-bold text-slate-100">Recent Analyses</h2>
          </div>
          <Link
            to="/history"
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            View Full History <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <ScanHistoryTable scans={recentScans} isLoading={isLoadingHistory} />
      </div>
    </div>
  );
}
