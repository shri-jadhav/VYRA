import React, { useState } from 'react';
import { Search, Code2, X } from 'lucide-react';
import { Asset } from '../types';

interface AssetsViewProps {
  assets: Asset[];
  isLoading: boolean;
}

export const AssetsView: React.FC<AssetsViewProps> = ({ assets, isLoading }) => {
  const [search, setSearch] = useState('');
  const [serviceFilter, setServiceFilter] = useState('ALL');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  const filteredAssets = assets.filter((a) => {
    const matchesService = serviceFilter === 'ALL' || a.service.toLowerCase() === serviceFilter.toLowerCase();
    const matchesSearch =
      !search ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.arn.toLowerCase().includes(search.toLowerCase()) ||
      a.asset_type.toLowerCase().includes(search.toLowerCase());
    return matchesService && matchesSearch;
  });

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* View Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Discovered Assets ({filteredAssets.length})
            </h1>
            <span className="text-xs text-[#737378] font-mono">
              of {assets.length} total
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Inventory of evaluated AWS cloud resources discovered via read-only assessment collectors.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* iOS Segmented Service Filter */}
          <div className="bg-[#141414] p-1 rounded-xl border border-[#2A2A2A] flex space-x-1 text-xs">
            {['ALL', 'S3', 'IAM', 'CLOUDTRAIL'].map((srv) => (
              <button
                key={srv}
                onClick={() => setServiceFilter(srv)}
                className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                  serviceFilter === srv
                    ? 'bg-[#252525] text-white font-medium shadow-sm'
                    : 'text-[#737378] hover:text-[#A1A1A6]'
                }`}
              >
                {srv}
              </button>
            ))}
          </div>

          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#737378]" />
            <input
              type="text"
              placeholder="Search assets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] placeholder-[#737378] focus:outline-none focus:border-[#3A3A3A] w-48 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Grouped Assets Table */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] overflow-hidden">
        <div className="overflow-x-auto max-h-[680px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] sticky top-0 z-10 border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-3">Resource Name & ARN</th>
                <th className="p-3">Service</th>
                <th className="p-3">Asset Type</th>
                <th className="p-3">Region</th>
                <th className="p-3">Discovered</th>
                <th className="p-3 text-right">Raw Config</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#737378] font-mono">
                    Loading asset inventory...
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#737378] font-mono">
                    No assets matching filter criteria found.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((a) => (
                  <tr key={a.id} className="hover:bg-[#181818] transition-colors">
                    <td className="p-3 font-medium text-[#F5F5F7]">
                      <div className="flex flex-col">
                        <span className="font-semibold text-white">{a.name}</span>
                        <span className="text-[10px] text-[#737378] truncate max-w-md">{a.arn}</span>
                      </div>
                    </td>
                    <td className="p-3 uppercase">
                      <span className="px-2 py-0.5 rounded-full bg-[#181818] border border-[#2A2A2A] text-[#D6D6D6] text-[10px]">
                        {a.service}
                      </span>
                    </td>
                    <td className="p-3 text-[#A1A1A6] text-[11px]">{a.asset_type}</td>
                    <td className="p-3 text-[#737378] text-[11px]">{a.region}</td>
                    <td className="p-3 text-[#737378] text-[10px]">
                      {new Date(a.last_seen).toUTCString()}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedAsset(a)}
                        className="px-2.5 py-1 rounded-xl bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-[#F5F5F7] text-xs font-mono inline-flex items-center space-x-1.5 transition-colors"
                      >
                        <Code2 className="w-3.5 h-3.5 text-[#A1A1A6]" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Config Modal / Apple Sheet */}
      {selectedAsset && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-[#2A2A2A] flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white font-mono">{selectedAsset.name}</h3>
                <p className="text-[11px] font-mono text-[#737378] truncate max-w-xl">{selectedAsset.arn}</p>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="p-1.5 rounded-xl hover:bg-[#181818] text-[#737378] hover:text-[#F5F5F7] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 overflow-y-auto flex-1 bg-[#0A0A0A]">
              <pre className="font-mono text-xs text-[#D6D6D6] p-3 rounded-xl border border-[#2A2A2A] bg-[#101010] overflow-x-auto leading-relaxed">
                {JSON.stringify(selectedAsset.configuration_data, null, 2)}
              </pre>
            </div>
            <div className="p-3.5 border-t border-[#2A2A2A] bg-[#141414] flex justify-between items-center text-xs text-[#737378]">
              <span>Sanitized by VYRA Credential Guard</span>
              <button
                onClick={() => setSelectedAsset(null)}
                className="px-4 py-1.5 rounded-xl bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
