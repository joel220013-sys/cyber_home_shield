import React from 'react';
import { RefreshCw, Shield, Zap, User as UserIcon, LogOut, LogIn, UserPlus } from 'lucide-react';
import { getRiskLevel } from '../../lib/utils';
import { useAuth } from '../../context/AuthContext';

interface HeaderProps {
  title: string;
  subtitle?: string;
  riskScore?: number;
  loading?: boolean;
  onRefresh?: () => void;
  onOpenAdvisor?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  riskScore = 0,
  loading = false,
  onRefresh,
  onOpenAdvisor,
}) => {
  const risk = getRiskLevel(riskScore);
  const { user, isAuthenticated, logout, openAuthModal } = useAuth();

  return (
    <header className="sticky top-0 z-20 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 backdrop-blur">
      <div>
        <h2 className="text-base font-bold text-slate-100 tracking-tight">{title}</h2>
        {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-3">
        {/* Network Risk Pill */}
        <div
          className={`hidden sm:flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${risk.badgeBg} ${risk.badgeBorder} ${risk.badgeText}`}
        >
          <Shield className="h-3.5 w-3.5" />
          <span>{risk.label}: {Math.round(riskScore)}/100</span>
        </div>

        {/* Quick Nemotron Shortcut */}
        {onOpenAdvisor && (
          <button
            onClick={onOpenAdvisor}
            className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-900/40 transition-colors shadow-sm"
          >
            <Zap className="h-3.5 w-3.5 text-emerald-400" />
            <span className="hidden md:inline">CipherX</span>
          </button>
        )}

        {/* Refresh Button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            title="Refresh security posture"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        )}

        {/* Authentication State & Controls */}
        <div className="flex items-center pl-2 border-l border-slate-800 gap-2">
          {isAuthenticated && user ? (
            <div className="flex items-center gap-2">
              <div className="hidden lg:flex flex-col text-right">
                <span className="text-xs font-semibold text-slate-200 truncate max-w-[140px]">
                  {user.full_name || user.email.split('@')[0]}
                </span>
                <span className="text-[10px] text-cyan-400 font-mono">
                  {user.authorized_network_scope}
                </span>
              </div>
              <button
                id="btn-user-logout"
                onClick={logout}
                title="Sign Out"
                className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-rose-300 transition-colors"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <button
                id="btn-header-login"
                onClick={() => openAuthModal('login')}
                className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 hover:text-white transition-colors"
              >
                <LogIn className="h-3.5 w-3.5 text-cyan-400" />
                <span>Sign In</span>
              </button>
              <button
                id="btn-header-register"
                onClick={() => openAuthModal('register')}
                className="hidden sm:flex items-center gap-1 rounded-lg bg-cyan-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-cyan-500 transition-colors shadow-sm shadow-cyan-500/20"
              >
                <UserPlus className="h-3.5 w-3.5" />
                <span>Register</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
