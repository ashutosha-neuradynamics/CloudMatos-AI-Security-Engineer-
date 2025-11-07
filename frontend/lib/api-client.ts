/**
 * API client for Prompt Firewall backend.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface QueryRequest {
  prompt?: string;
  response?: string;
}

export interface Risk {
  type: string;
  severity: 'high' | 'medium' | 'low';
  match: string;
  position: { start: number; end: number };
  explanation: string;
}

export interface QueryResponse {
  decision: 'block' | 'redact' | 'warn' | 'allow';
  promptModified?: string;
  responseModified?: string;
  risks: Risk[];
  explanation: string;
  metadata: {
    requestId: string;
    timestamp: string;
  };
}

export interface PolicyRule {
  id?: number;
  name: string;
  description?: string;
  risk_type: string;
  pattern: string;
  pattern_type: string;
  severity: string;
  action: string;
  enabled: boolean;
}

export interface PolicyResponse {
  rules: PolicyRule[];
}

export interface LogEntry {
  id: number;
  request_id: string;
  timestamp: string;
  original_prompt?: string;
  modified_prompt?: string;
  original_response?: string;
  modified_response?: string;
  decision: string;
  risks: Risk[];
  metadata: Record<string, any>;
}

export interface LogsResponse {
  logs: LogEntry[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export class APIError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public response?: any
  ) {
    super(message);
    this.name = 'APIError';
  }
}

async function fetchAPI<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    let errorData;
    try {
      errorData = await response.json();
    } catch {
      errorData = { detail: response.statusText };
    }
    throw new APIError(
      errorData.detail || `API request failed: ${response.statusText}`,
      response.status,
      errorData
    );
  }

  return response.json();
}

export const apiClient = {
  async query(request: QueryRequest): Promise<QueryResponse> {
    return fetchAPI<QueryResponse>('/v1/query', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  },

  async getPolicy(): Promise<PolicyResponse> {
    return fetchAPI<PolicyResponse>('/v1/policy');
  },

  async updatePolicy(rules: PolicyRule[]): Promise<PolicyResponse> {
    return fetchAPI<PolicyResponse>('/v1/policy', {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    });
  },

  async getLogs(params?: {
    type?: string;
    severity?: string;
    date_from?: string;
    date_to?: string;
    limit?: number;
    offset?: number;
    format?: 'json' | 'csv';
  }): Promise<LogsResponse | string> {
    const queryParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          queryParams.append(key, String(value));
        }
      });
    }
    
    const endpoint = `/v1/logs${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    
    if (params?.format === 'csv') {
      const response = await fetch(`${API_BASE_URL}${endpoint}`);
      if (!response.ok) {
        throw new APIError(`Failed to fetch logs: ${response.statusText}`, response.status);
      }
      return response.text();
    }
    
    return fetchAPI<LogsResponse>(endpoint);
  },

  async healthCheck(): Promise<{ status: string }> {
    return fetchAPI<{ status: string }>('/v1/health');
  },

  async login(username: string, password: string): Promise<{ access_token: string; token_type: string }> {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await fetch(`${API_BASE_URL}/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch {
        errorData = { detail: response.statusText };
      }
      throw new APIError(
        errorData.detail || `Login failed: ${response.statusText}`,
        response.status,
        errorData
      );
    }

    return response.json();
  },
};

