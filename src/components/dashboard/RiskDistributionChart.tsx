import React from 'react';
import { Card } from '../common/Card';
import { NetworkPostureResult, Device } from '../../types';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface RiskDistributionChartProps {
  posture: NetworkPostureResult | null;
  devices: Device[];
}

export const RiskDistributionChart: React.FC<RiskDistributionChartProps> = ({
  posture,
  devices,
}) => {
  if (!posture || devices.length === 0) {
    return (
      <Card title="Device Risk Distribution" subtitle="Risk scores by connected asset">
        <p className="text-xs text-slate-400 py-12 text-center">No security data available</p>
      </Card>
    );
  }

  // Format devices for bar chart
  const data = devices.map((d) => {
    const score = d.risk_score ?? posture.device_scores[d.id] ?? 0;
    return {
      name: d.hostname || d.ip_address,
      ip: d.ip_address,
      type: d.device_type,
      score: Math.round(score),
    };
  });

  const getBarColor = (score: number) => {
    if (score >= 80) return '#ef4444'; // critical red
    if (score >= 60) return '#f97316'; // high orange
    if (score >= 35) return '#eab308'; // medium amber
    return '#10b981'; // low emerald
  };

  return (
    <Card
      title="Device Risk Distribution"
      subtitle="Defensive score evaluation per endpoint (0 to 100)"
    >
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
            <XAxis
              dataKey="name"
              stroke="#64748b"
              fontSize={10}
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
              interval={0}
              angle={-25}
              textAnchor="end"
            />
            <YAxis
              domain={[0, 100]}
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#334155' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: '#334155',
                borderRadius: '8px',
                fontSize: '12px',
                color: '#f8fafc',
              }}
              formatter={(val: any) => [`${val} / 100`, 'Risk Score']}
              labelFormatter={(label: any) => `Endpoint: ${label}`}
            />
            <Bar dataKey="score" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
};
