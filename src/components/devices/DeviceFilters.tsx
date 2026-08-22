import React from 'react';
import { Search, Filter, ArrowUpDown } from 'lucide-react';
import { DeviceType } from '../../types';

interface DeviceFiltersProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  typeFilter: string;
  onTypeChange: (t: string) => void;
  sortBy: string;
  onSortByChange: (s: any) => void;
  sortOrder: 'asc' | 'desc';
  onToggleSortOrder: () => void;
}

const DEVICE_TYPES: { label: string; value: string }[] = [
  { label: 'All Types', value: 'ALL' },
  { label: 'Routers & Gateways', value: 'ROUTER' },
  { label: 'Cameras (IP)', value: 'IP_CAMERA' },
  { label: 'Storage (NAS)', value: 'NAS' },
  { label: 'IoT Devices', value: 'IOT' },
  { label: 'Smart TVs', value: 'SMART_TV' },
  { label: 'Printers', value: 'PRINTER' },
  { label: 'Workstations / Laptops', value: 'LAPTOP' },
];

export const DeviceFilters: React.FC<DeviceFiltersProps> = ({
  searchQuery,
  onSearchChange,
  typeFilter,
  onTypeChange,
  sortBy,
  onSortByChange,
  sortOrder,
  onToggleSortOrder,
}) => {
  return (
    <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
      {/* Search Input */}
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search by IP, hostname, vendor, or MAC..."
          className="w-full rounded-lg border border-slate-800 bg-slate-900/90 pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-400 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        />
      </div>

      {/* Type & Sort Filters */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-1.5">
          <Filter className="h-3.5 w-3.5 text-slate-400" />
          <select
            value={typeFilter}
            onChange={(e) => onTypeChange(e.target.value)}
            className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
          >
            {DEVICE_TYPES.map((t) => (
              <option key={t.value} value={t.value} className="bg-slate-900 text-slate-200">
                {t.label}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={onToggleSortOrder}
          title={`Sort ${sortOrder === 'desc' ? 'Ascending' : 'Descending'}`}
          className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-2 text-xs text-slate-300 hover:text-white transition-colors"
        >
          <ArrowUpDown className="h-3.5 w-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Sort Risk</span>
        </button>
      </div>
    </div>
  );
};
