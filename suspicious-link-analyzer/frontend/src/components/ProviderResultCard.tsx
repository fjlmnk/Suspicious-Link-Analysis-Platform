import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Ban,
  Server,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import type { ProviderVerdict } from '@/types';

interface ProviderResultCardProps {
  verdict: ProviderVerdict;
}

function getProviderIcon(name: string) {
  const lower = name.toLowerCase();
  if (lower.includes('virustotal')) return <Server className="w-5 h-5" />;
  if (lower.includes('google')) return <ShieldCheck className="w-5 h-5" />;
  return <Server className="w-5 h-5" />;
}

function getStatusInfo(status: string): { label: string; color: string; icon: React.ReactNode } {
  const s = status.toLowerCase();
  if (s === 'success' || s === 'completed') {
    return { label: 'Success', color: 'text-emerald-400', icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" /> };
  }
  if (s === 'error' || s === 'failed') {
    return { label: 'Error', color: 'text-red-400', icon: <XCircle className="w-4 h-4 text-red-400" /> };
  }
  if (s === 'timeout') {
    return { label: 'Timeout', color: 'text-amber-400', icon: <Clock className="w-4 h-4 text-amber-400" /> };
  }
  if (s === 'rate_limited' || s === 'rate limited') {
    return { label: 'Rate Limited', color: 'text-amber-400', icon: <AlertTriangle className="w-4 h-4 text-amber-400" /> };
  }
  if (s === 'unavailable') {
    return { label: 'Unavailable', color: 'text-slate-500', icon: <Ban className="w-4 h-4 text-slate-500" /> };
  }
  return { label: status, color: 'text-slate-400', icon: <Server className="w-4 h-4 text-slate-400" /> };
}

export default function ProviderResultCard({ verdict }: ProviderResultCardProps) {
  const statusInfo = getStatusInfo(verdict.provider_status);
  const borderColor = verdict.is_malicious
    ? 'border-red-500/40'
    : 'border-emerald-500/30';

  return (
    <div className={`card p-5 border-l-4 ${borderColor} transition-all duration-300 hover:shadow-lg`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-700/50">
            {getProviderIcon(verdict.provider_name)}
          </div>
          <div>
            <h3 className="font-semibold text-white">{verdict.provider_name}</h3>
            <div className="flex items-center gap-1.5">
              {statusInfo.icon}
              <span className={`text-xs ${statusInfo.color}`}>{statusInfo.label}</span>
            </div>
          </div>
        </div>

        {/* Verdict badge */}
        <div
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium ${
            verdict.is_malicious
              ? 'bg-red-500/10 text-red-400 border border-red-500/30'
              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
          }`}
        >
          {verdict.is_malicious ? (
            <>
              <ShieldAlert className="w-4 h-4" />
              Malicious
            </>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4" />
              Clean
            </>
          )}
        </div>
      </div>

      {/* Details */}
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span className="text-slate-500 block text-xs mb-0.5">Detections</span>
          <span className={`font-medium ${verdict.detection_count > 0 ? 'text-red-400' : 'text-slate-300'}`}>
            {verdict.detection_count} found
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-xs mb-0.5">Category</span>
          <span className="font-medium text-slate-300">{verdict.category || 'N/A'}</span>
        </div>
      </div>
    </div>
  );
}
