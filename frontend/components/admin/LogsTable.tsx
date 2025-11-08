/**
 * Logs table component for displaying firewall logs.
 */

'use client';

import { useState, useEffect } from 'react';
import { apiClient, LogEntry, LogsResponse, APIError } from '@/lib/api-client';

interface LogsTableProps {
  filters?: {
    type?: string;
    severity?: string;
    date_from?: string;
    date_to?: string;
  };
}

export default function LogsTable({ filters }: LogsTableProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [clientMode, setClientMode] = useState(false);
  const [clientAll, setClientAll] = useState<LogEntry[]>([]);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const hasTypeOrSeverity = Boolean(filters?.type || filters?.severity);

      if (hasTypeOrSeverity) {
        // Fetch a larger batch without type/severity to avoid backend JSON LIKE error, then filter client-side
        const { type, severity, ...rest } = filters || {};
        const response = await apiClient.getLogs({
          ...rest,
          limit: 1000,
          offset: 0,
          format: 'json',
        }) as LogsResponse;

        const filtered = response.logs.filter((log) => {
          const risks = log.risks || [];
          const typeOk = type ? risks.some((r) => r.type === type) : true;
          const severityOk = severity ? risks.some((r) => r.severity === severity) : true;
          return typeOk && severityOk;
        });

        setClientMode(true);
        setClientAll(filtered);
        setTotal(filtered.length);
        setHasMore(offset + limit < filtered.length);
        setLogs(filtered.slice(offset, offset + limit));
      } else {
        // Normal server-side pagination when no problematic filters are used
        const response = await apiClient.getLogs({
          ...filters,
          limit,
          offset,
          format: 'json',
        }) as LogsResponse;
        
        setClientMode(false);
        setClientAll([]);
        setLogs(response.logs);
        setTotal(response.total);
        setHasMore(response.has_more);
      }
    } catch (err) {
      if (err instanceof APIError) {
        setError(err.message);
      } else {
        setError('Failed to fetch logs');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [limit, offset, filters]);

  // When in client-side mode and user changes page size or offset, recompute from cached filtered results
  useEffect(() => {
    if (clientMode) {
      setLogs(clientAll.slice(offset, offset + limit));
      setHasMore(offset + limit < clientAll.length);
      setTotal(clientAll.length);
    }
  }, [clientMode, clientAll, limit, offset]);

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const hasTypeOrSeverity = Boolean(filters?.type || filters?.severity);

      if (hasTypeOrSeverity) {
        // Client-side export when type/severity is used to avoid backend JSON LIKE error
        const { type, severity, ...rest } = filters || {};
        const response = await apiClient.getLogs({
          ...rest,
          limit: 1000,
          offset: 0,
          format: 'json',
        }) as LogsResponse;

        const filtered = response.logs.filter((log) => {
          const risks = log.risks || [];
          const typeOk = type ? risks.some((r) => r.type === type) : true;
          const severityOk = severity ? risks.some((r) => r.severity === severity) : true;
          return typeOk && severityOk;
        });

        if (format === 'csv') {
          // Mirror backend CSV shape: id, request_id, timestamp, decision, risk_count
          const header = 'id,request_id,timestamp,decision,risk_count\n';
          const rows = filtered.map((log) => {
            const cols = [
              String(log.id),
              `"${log.request_id}"`,
              `"${log.timestamp}"`,
              `"${log.decision}"`,
              String(log.risks?.length ?? 0),
            ];
            return cols.join(',');
          });
          const csv = header + rows.join('\n');
          const blob = new Blob([csv], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `logs-${new Date().toISOString().split('T')[0]}.csv`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        } else {
          const blob = new Blob([JSON.stringify({
            logs: filtered,
            total: filtered.length,
            limit: filtered.length,
            offset: 0,
            has_more: false,
          }, null, 2)], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `logs-${new Date().toISOString().split('T')[0]}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        }
      } else {
        // Server-side export when no problematic filters are present
        const data = await apiClient.getLogs({
          ...filters,
          limit: 1000,
          offset: 0,
          format,
        });
        
        if (format === 'csv') {
          const blob = new Blob([data as string], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `logs-${new Date().toISOString().split('T')[0]}.csv`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        } else {
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `logs-${new Date().toISOString().split('T')[0]}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        }
      }
    } catch (err) {
      alert('Failed to export logs');
    }
  };

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case 'block':
        return 'bg-red-100 text-red-800';
      case 'redact':
        return 'bg-yellow-100 text-yellow-800';
      case 'warn':
        return 'bg-orange-100 text-orange-800';
      case 'allow':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading && logs.length === 0) {
    return <div className="text-center py-8">Loading logs...</div>;
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <p className="text-red-800">Error: {error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <p className="text-sm text-gray-600">
            Showing {offset + 1}-{Math.min(offset + limit, total)} of {total} logs
          </p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => handleExport('csv')}
            className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 text-sm"
          >
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 text-sm"
          >
            Export JSON
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Timestamp
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Decision
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Risks
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Request ID
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getDecisionColor(log.decision)}`}>
                    {log.decision}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {log.risks.length} risk{log.risks.length !== 1 ? 's' : ''}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">
                  {log.request_id.substring(0, 8)}...
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex justify-between items-center">
        <button
          onClick={() => setOffset(Math.max(0, offset - limit))}
          disabled={offset === 0}
          className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-sm"
        >
          Previous
        </button>
        <button
          onClick={() => setOffset(offset + limit)}
          disabled={!hasMore}
          className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-sm"
        >
          Next
        </button>
      </div>
    </div>
  );
}

