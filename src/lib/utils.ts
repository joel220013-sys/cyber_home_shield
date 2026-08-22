import { Severity, BaselineStatus } from '../types';

/**
 * Combine class names cleanly
 */
export function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}

/**
 * Return human readable risk level string
 */
export function getRiskLevel(score: number): {
  label: string;
  color: string;
  badgeBg: string;
  badgeBorder: string;
  badgeText: string;
} {
  if (score >= 80) {
    return {
      label: 'CRITICAL RISK',
      color: '#ef4444',
      badgeBg: 'bg-red-500/10',
      badgeBorder: 'border-red-500/30',
      badgeText: 'text-red-400',
    };
  }
  if (score >= 60) {
    return {
      label: 'HIGH RISK',
      color: '#f97316',
      badgeBg: 'bg-orange-500/10',
      badgeBorder: 'border-orange-500/30',
      badgeText: 'text-orange-400',
    };
  }
  if (score >= 35) {
    return {
      label: 'MEDIUM RISK',
      color: '#eab308',
      badgeBg: 'bg-amber-500/10',
      badgeBorder: 'border-amber-500/30',
      badgeText: 'text-amber-400',
    };
  }
  if (score > 0) {
    return {
      label: 'LOW RISK',
      color: '#10b981',
      badgeBg: 'bg-emerald-500/10',
      badgeBorder: 'border-emerald-500/30',
      badgeText: 'text-emerald-400',
    };
  }
  return {
    label: 'SECURE',
    color: '#06b6d4',
    badgeBg: 'bg-cyan-500/10',
    badgeBorder: 'border-cyan-500/30',
    badgeText: 'text-cyan-400',
  };
}

/**
 * Return visual tokens for finding & threat severity
 */
export function getSeverityTokens(severity: Severity | string) {
  const norm = (severity || '').toUpperCase();
  switch (norm) {
    case 'CRITICAL':
      return {
        label: 'CRITICAL',
        bg: 'bg-red-950/40',
        text: 'text-red-400',
        border: 'border-red-500/40',
        dot: 'bg-red-500',
      };
    case 'HIGH':
      return {
        label: 'HIGH',
        bg: 'bg-orange-950/40',
        text: 'text-orange-400',
        border: 'border-orange-500/40',
        dot: 'bg-orange-500',
      };
    case 'MEDIUM':
      return {
        label: 'MEDIUM',
        bg: 'bg-amber-950/40',
        text: 'text-amber-400',
        border: 'border-amber-500/40',
        dot: 'bg-amber-500',
      };
    case 'LOW':
      return {
        label: 'LOW',
        bg: 'bg-emerald-950/40',
        text: 'text-emerald-400',
        border: 'border-emerald-500/40',
        dot: 'bg-emerald-500',
      };
    case 'INFO':
    default:
      return {
        label: 'INFO',
        bg: 'bg-slate-800/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        dot: 'bg-slate-400',
      };
  }
}

/**
 * Format timestamps nicely
 */
export function formatTimestamp(isoStr?: string | null): string {
  if (!isoStr) return 'Never';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return isoStr;
  }
}

/**
 * Validate private IPv4 / RFC 1918 scope format
 */
export function isPrivateSubnet(target: string): boolean {
  const clean = target.trim();
  const cidrRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;
  const match = clean.match(cidrRegex);
  if (!match) return false;

  const o1 = parseInt(match[1], 10);
  const o2 = parseInt(match[2], 10);
  const o3 = parseInt(match[3], 10);
  const o4 = parseInt(match[4], 10);
  const mask = match[6] ? parseInt(match[6], 10) : 32;

  if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255 || mask > 32 || mask < 8) {
    return false;
  }

  // RFC1918 Private Ranges:
  // 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
  if (o1 === 10) return true;
  // 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  // 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
  if (o1 === 192 && o2 === 168) return true;

  return false;
}

export const isValidIPv4Subnet = isPrivateSubnet;
