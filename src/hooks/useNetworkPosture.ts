import { useState, useEffect, useCallback, useRef } from 'react';
import { NetworkPostureResult } from '../types';
import { riskService } from '../services/riskService';

export function useNetworkPosture() {
  const [posture, setPosture] = useState<NetworkPostureResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Prevent duplicate initial API calls in React Strict Mode
  const hasFetchedRef = useRef(false);

  const fetchPosture = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await riskService.getNetworkPosture();

      setPosture(data);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : 'Failed to load security posture';

      console.error('Failed to fetch network posture:', err);

      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Prevent duplicate request caused by React Strict Mode
    if (hasFetchedRef.current) {
      return;
    }

    hasFetchedRef.current = true;

    void fetchPosture();
  }, [fetchPosture]);

  return {
    posture,
    loading,
    error,
    refresh: fetchPosture,
  };
}