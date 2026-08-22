/**
 * Authentication Context & Hook
 * Provides secure session state across Cyber Home Shield frontend.
 */

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, UserLoginRequest, UserRegisterRequest } from '../types';
import { authService } from '../services/authService';
import { getAuthToken, setAuthToken } from '../services/api';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: UserLoginRequest) => Promise<void>;
  register: (data: UserRegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (data: { full_name?: string; authorized_network_scope?: string }) => Promise<void>;
  authModalOpen: boolean;
  authModalMode: 'login' | 'register';
  openAuthModal: (mode?: 'login' | 'register') => void;
  closeAuthModal: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login');

  useEffect(() => {
    async function checkExistingAuth() {
      const token = getAuthToken();
      if (!token) {
        setIsLoading(false);
        return;
      }
      try {
        const currentUser = await authService.getMe();
        setUser(currentUser);
      } catch (err) {
        // Token invalid or expired
        setAuthToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    }
    checkExistingAuth();
  }, []);

  const login = async (credentials: UserLoginRequest) => {
    setIsLoading(true);
    try {
      const res = await authService.login(credentials);
      setUser(res.user);
      setAuthModalOpen(false);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (data: UserRegisterRequest) => {
    setIsLoading(true);
    try {
      const res = await authService.register(data);
      setUser(res.user);
      setAuthModalOpen(false);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await authService.logout();
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const updateProfile = async (data: { full_name?: string; authorized_network_scope?: string }) => {
    const updated = await authService.updateMe(data);
    setUser(updated);
  };

  const openAuthModal = (mode: 'login' | 'register' = 'login') => {
    setAuthModalMode(mode);
    setAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setAuthModalOpen(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        updateProfile,
        authModalOpen,
        authModalMode,
        openAuthModal,
        closeAuthModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
