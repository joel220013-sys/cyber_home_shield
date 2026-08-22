import React from 'react';
import { Card } from '../common/Card';
import { NetworkPostureResult } from '../../types';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from 'recharts';

interface SeverityBreakdownChartProps {
  posture: NetworkPostureResult | null;
}

export const SeverityBreakdownChart: React.FC<SeverityBreakdownChartProps> = ({ posture }) => {
  if (!posture) {
    return (
      <Card title="Security Findings by Severity" subtitle="Vulnerability categorization">
        <p className="text-xs text-slate-400 py-12 text-center">No security data available</p>
      </Card>
    );
  }

  const total =
    posture.critical_findings +
    posture.high_findings +
    posture.medium_findings +
    posture.low_findings;

  const data = [
    { name: 'Critical', value: posture.critical_findings, color: '#ef4444' },
    { name: 'High', value: posture.high_findings, color: '#f97316' },
    { name: 'Medium', value: posture.medium_findings, color: '#eab308' },
    { name: 'Low', value: posture.low_findings, color: '#10b981' },
  ].filter((d) => d.value > 0);

  return (
    <Card
      title="Security Findings by Severity"
      subtitle={`${total} active finding${total === 1 ? '' : 's'} across network`}
    >
      <div className="h-64 w-full">
        {data.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-center">
            <span className="text-xs font-medium text-emerald-400">Zero active vulnerabilities</span>
            <p className="text-[11px] text-slate-400 mt-1">All monitored hosts within secure parameters</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: '#f8fafc',
                }}
                formatter={(val: any, name: any) => [`${val} finding(s)`, name]}
              />
              <Legend
                verticalAlign="bottom"
                iconType="circle"
                wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
};
