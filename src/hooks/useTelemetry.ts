import { useCallback, useEffect, useState } from 'react';
import { NetworkEvent } from '../types';
import { telemetryService } from '../services/telemetryService';
import { useAuth } from '../context/AuthContext';

export function useTelemetry() {
  const { isAuthenticated, isLoading: isAuthLoading } = useAuth();
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setEvents(await telemetryService.getEvents());
    } catch (err: any) {
      setError(err.message || 'Failed to load network telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAuthLoading) return;

    if (!isAuthenticated) {
      setLoading(false);
      setError('Sign in to view network telemetry.');
      return;
    }

    void fetchEvents();
  }, [fetchEvents, isAuthLoading, isAuthenticated]);

  return { events, loading, error, refresh: fetchEvents };
}