import { useState, useEffect, useCallback, useMemo } from 'react';
import { Device, DeviceType } from '../types';
import { deviceService } from '../services/deviceService';

export function useDevices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'risk_score' | 'ip_address' | 'hostname' | 'last_seen'>('risk_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const fetchDevices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await deviceService.getDevices();
      setDevices(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load devices');
    } finally {
      setLoading(false);
    }
  }, []);

  const discoverInventory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setDevices(await deviceService.discoverInventory());
    } catch (err: any) {
      setError(err.message || 'Failed to refresh device inventory');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const filteredDevices = useMemo(() => {
    return devices
      .filter((dev) => {
        // Text search match
        const matchesQuery =
          !searchQuery ||
          dev.ip_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
          (dev.hostname && dev.hostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
          (dev.vendor && dev.vendor.toLowerCase().includes(searchQuery.toLowerCase())) ||
          (dev.mac_address && dev.mac_address.toLowerCase().includes(searchQuery.toLowerCase()));

        // Type filter match
        const matchesType = typeFilter === 'ALL' || dev.device_type === typeFilter;

        return matchesQuery && matchesType;
      })
      .sort((a, b) => {
        let valA = a[sortBy] ?? 0;
        let valB = b[sortBy] ?? 0;

        if (typeof valA === 'string') {
          valA = valA.toLowerCase();
          valB = (valB as string).toLowerCase();
        }

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
        return 0;
      });
  }, [devices, searchQuery, typeFilter, sortBy, sortOrder]);

  return {
    devices,
    filteredDevices,
    loading,
    error,
    searchQuery,
    setSearchQuery,
    typeFilter,
    setTypeFilter,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    refresh: fetchDevices,
    discoverInventory,
  };
}
