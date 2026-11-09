import { ShieldCheck, ShieldAlert, Skull, Loader2, ShieldX } from 'lucide-react';
import { ScanStatus, ThreatLevel } from '@/types';

interface ThreatBadgeProps {
  threatLevel?: ThreatLevel;
  level?: ThreatLevel;
  status?: ScanStatus;
  size?: 'sm' | 'md' | 'lg';
}

export default function ThreatBadge({ threatLevel, level, status, size = 'md' }: ThreatBadgeProps) {
  const actualLevel = threatLevel ?? level;

  // If status is not COMPLETED, show status-based badge
  if (status === ScanStatus.PENDING) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border threat-pending ${sizeClasses(size)}`}>
        <Loader2 className={`animate-spin ${iconSize(size)}`} />
        Scanning...
      </span>
    );
  }

  if (status === ScanStatus.FAILED) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border threat-failed ${sizeClasses(size)}`}>
        <ShieldX className={iconSize(size)} />
        Failed
      </span>
    );
  }

  // Threat level badges
  if (actualLevel === ThreatLevel.SAFE) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border threat-safe ${sizeClasses(size)}`}>
        <ShieldCheck className={iconSize(size)} />
        Safe
      </span>
    );
  }

  if (actualLevel === ThreatLevel.SUSPICIOUS) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border threat-suspicious ${sizeClasses(size)}`}>
        <ShieldAlert className={iconSize(size)} />
        Suspicious
      </span>
    );
  }

  if (actualLevel === ThreatLevel.DANGEROUS) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-semibold rounded-full border threat-dangerous animate-glow ${sizeClasses(size)}`}>
        <Skull className={iconSize(size)} />
        Dangerous
      </span>
    );
  }

  // Fallback
  return (
    <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border threat-pending ${sizeClasses(size)}`}>
      Unknown
    </span>
  );
}

function sizeClasses(size: 'sm' | 'md' | 'lg'): string {
  switch (size) {
    case 'sm':
      return 'px-2 py-0.5 text-xs';
    case 'md':
      return 'px-3 py-1 text-sm';
    case 'lg':
      return 'px-5 py-2.5 text-lg';
  }
}

function iconSize(size: 'sm' | 'md' | 'lg'): string {
  switch (size) {
    case 'sm':
      return 'w-3 h-3';
    case 'md':
      return 'w-4 h-4';
    case 'lg':
      return 'w-6 h-6';
  }
}
