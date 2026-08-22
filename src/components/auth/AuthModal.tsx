/**
 * Authentication Modal (Login & Registration)
 * Enforces defensive scope validation and secure credential entry.
 */

import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Mail,
  User as UserIcon,
  Network,
  AlertCircle,
  X,
  Loader2,
  CheckCircle2,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { isValidIPv4Subnet } from '../../lib/utils';

export const AuthModal: React.FC = () => {
  const { authModalOpen, authModalMode, closeAuthModal, openAuthModal, login, register } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [subnet, setSubnet] = useState('192.168.1.0/24');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!authModalOpen) return null;

  const isLogin = authModalMode === 'login';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !password) {
      setError('Please fill in all required fields.');
      return;
    }

    if (!isLogin) {
      if (password.length < 8) {
        setError('Password must be at least 8 characters long.');
        return;
      }
      if (!isValidIPv4Subnet(subnet)) {
        setError(
          'Target scope must be a valid private RFC 1918 CIDR subnet (e.g. 192.168.1.0/24 or 10.0.0.0/16).'
        );
        return;
      }
    }

    setIsSubmitting(true);
    try {
      if (isLogin) {
        await login({ email, password });
      } else {
        await register({
          email,
          password,
          full_name: fullName,
          authorized_network_scope: subnet,
        });
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      id="auth-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-200"
    >
      <div
        id="auth-modal-card"
        className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden p-6 sm:p-8 relative"
      >
        <button
          id="btn-close-auth-modal"
          onClick={closeAuthModal}
          className="absolute top-5 right-5 text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-lg hover:bg-slate-800"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">
              {isLogin ? 'Sign In to Home Shield' : 'Create Security Account'}
            </h2>
            <p className="text-xs text-slate-400">
              {isLogin
                ? 'Access your private network security dashboard'
                : 'Defensive home cybersecurity platform'}
            </p>
          </div>
        </div>

        {error && (
          <div
            id="auth-error-alert"
            className="mb-4 p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start space-x-3 text-rose-300 text-sm"
          >
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {!isLogin && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <UserIcon className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  id="input-auth-name"
                  type="text"
                  placeholder="Alex Administrator"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Email Address <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                id="input-auth-email"
                type="email"
                required
                placeholder="admin@homeshield.local"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Password <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                id="input-auth-password"
                type="password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors"
              />
            </div>
            {!isLogin && (
              <p className="text-[11px] text-slate-500 mt-1">Must be at least 8 characters.</p>
            )}
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Authorized Network Scope <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <Network className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  id="input-auth-subnet"
                  type="text"
                  required
                  placeholder="192.168.1.0/24"
                  value={subnet}
                  onChange={(e) => setSubnet(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors font-mono"
                />
              </div>
              <p className="text-[11px] text-cyan-400/80 mt-1">
                Strict RFC 1918 private IPv4 subnet boundaries only.
              </p>
            </div>
          )}

          <button
            id="btn-submit-auth"
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold py-3 px-4 rounded-xl shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 cursor-pointer"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>{isLogin ? 'Authenticating...' : 'Creating Account...'}</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-4 h-4" />
                <span>{isLogin ? 'Sign In' : 'Complete Registration'}</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
          {isLogin ? (
            <p className="text-xs text-slate-400">
              Need a security account?{' '}
              <button
                type="button"
                onClick={() => openAuthModal('register')}
                className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-2 ml-1"
              >
                Register here
              </button>
            </p>
          ) : (
            <p className="text-xs text-slate-400">
              Already registered?{' '}
              <button
                type="button"
                onClick={() => openAuthModal('login')}
                className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-2 ml-1"
              >
                Sign In
              </button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
