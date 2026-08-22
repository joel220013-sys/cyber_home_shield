import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Loading security data...',
  size = 'md',
}) => {
  const iconSize = size === 'lg' ? 'h-8 w-8' : size === 'md' ? 'h-6 w-6' : 'h-4 w-4';

  return (
    <div className="flex flex-col items-center justify-center p-8 text-center space-y-3">
      <Loader2 className={`${iconSize} animate-spin text-cyan-400`} />
      {message && <p className="text-xs font-medium text-slate-400 animate-pulse">{message}</p>}
    </div>
  );
};
