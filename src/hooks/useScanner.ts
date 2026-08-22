import { useState, useCallback, useRef, useEffect } from 'react';
import { ScanJob, ScanType } from '../types';
import { scanService } from '../services/scanService';

export function useScanner() {
  const [activeJob, setActiveJob] = useState<ScanJob | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanJob[]>([]);

  const pollIntervalRef = useRef<any>(null);

  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const pollJobStatus = useCallback(
    (jobId: string) => {
      stopPolling();
      pollIntervalRef.current = setInterval(async () => {
        try {
          const updated = await scanService.getScan(jobId);
          setActiveJob(updated);

          if (updated.status === 'COMPLETED' || updated.status === 'FAILED' || updated.status === 'CANCELLED') {
            setIsScanning(false);
            stopPolling();
            setScanHistory((prev) => [updated, ...prev.filter((j) => j.id !== updated.id)]);
          }
        } catch (err: any) {
          console.error('Error polling scan status:', err);
        }
      }, 2500); // Polling every 2.5 seconds (non-aggressive)
    },
    [stopPolling]
  );

  const startScan = useCallback(
    async (targetSubnet: string, scanType: ScanType = 'DISCOVERY', dryRun: boolean = false) => {
      setIsScanning(true);
      setError(null);

      try {
        const job = await scanService.createScan({
          target_subnet: targetSubnet,
          scan_type: scanType,
          dry_run: dryRun,
        });

        setActiveJob(job);
        setScanHistory((prev) => [job, ...prev]);

        if (job.status === 'RUNNING' || job.status === 'PENDING') {
          pollJobStatus(job.id);
        } else {
          setIsScanning(false);
        }
        return job;
      } catch (err: any) {
        setIsScanning(false);
        const msg = err.message || 'Failed to initiate defensive scan';
        setError(msg);
        throw err;
      }
    },
    [pollJobStatus]
  );

  useEffect(() => {
    return () => {
      stopPolling();
    };
  }, [stopPolling]);

  return {
    activeJob,
    isScanning,
    error,
    scanHistory,
    startScan,
    stopPolling,
  };
}
