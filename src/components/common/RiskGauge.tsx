import React from 'react';
import { getRiskLevel } from '../../lib/utils';

interface RiskGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 'md',
  showLabel = true,
}) => {
  const safeScore = Math.min(100, Math.max(0, Math.round(score)));
  const risk = getRiskLevel(safeScore);

  const radius = size === 'lg' ? 68 : size === 'md' ? 48 : 32;
  const strokeWidth = size === 'lg' ? 10 : size === 'md' ? 8 : 6;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  // Use a 270 degree arc for gauge look
  const strokeDashoffset = circumference - (safeScore / 100) * (circumference * 0.75);

  const dimension = radius * 2 + 10;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center">
        <svg height={dimension} width={dimension} className="rotate-135 transform">
          {/* Background Track */}
          <circle
            stroke="#1e293b"
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            r={normalizedRadius}
            cx={dimension / 2}
            cy={dimension / 2}
            strokeLinecap="round"
          />
          {/* Active Score Arc */}
          <circle
            stroke={risk.color}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            style={{
              strokeDashoffset,
              transition: 'stroke-dashoffset 0.8s ease-in-out',
            }}
            r={normalizedRadius}
            cx={dimension / 2}
            cy={dimension / 2}
            strokeLinecap="round"
          />
        </svg>

        {/* Inner Score Text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={`font-bold tracking-tight text-white ${
              size === 'lg' ? 'text-3xl' : size === 'md' ? 'text-2xl' : 'text-base'
            }`}
          >
            {safeScore}
          </span>
          <span className="text-[10px] uppercase font-semibold text-slate-400">/ 100</span>
        </div>
      </div>

      {showLabel && (
        <div
          className={`mt-2 px-2.5 py-0.5 rounded-full border text-xs font-semibold uppercase tracking-wider ${risk.badgeBg} ${risk.badgeBorder} ${risk.badgeText}`}
        >
          {risk.label}
        </div>
      )}
    </div>
  );
};
