import { useCallback, useEffect, useRef, useState } from 'react';
import { SecurityFinding } from '../types';
import { findingsService } from '../services/findingsService';
import { useAuth } from '../context/AuthContext';

export function useFindings() {
  const { isAuthenticated, isLoading: isAuthLoading } = useAuth();
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const hasFetchedRef = useRef(false);

  const fetchFindings = useCallback(async () => {
    if (isAuthLoading) return;

    if (!isAuthenticated) {
      setLoading(false);
      setError('Sign in to view security findings.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await findingsService.getFindings();
      setFindings(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load security findings');
    } finally {
      setLoading(false);
    }
  }, [isAuthLoading, isAuthenticated]);

  useEffect(() => {
    if (isAuthLoading) return;
    if (hasFetchedRef.current) return;

    if (!isAuthenticated) {
      void fetchFindings();
      return;
    }

    hasFetchedRef.current = true;
    void fetchFindings();
  }, [fetchFindings, isAuthLoading, isAuthenticated]);

  return {
    findings,
    loading,
    error,
    refresh: fetchFindings,
  };
}