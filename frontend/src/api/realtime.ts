import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import apiClient from '../lib/api';
import { queryKeys } from './hooks';

export type RealTimeConnectionState = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING' | 'DISCONNECTED' | 'UNAUTHORIZED';

export interface RealTimeEvent {
  event_id: string;
  event_type: 'ANALYSIS_COMPLETED' | 'ANALYSIS_FAILED' | 'THREAT_DETECTED' | 'IOC_CREATED' | 'CAMPAIGN_UPDATED';
  workspace_id: string;
  timestamp: string;
  severity?: string;
  title: string;
  message: string;
  resource_type?: string;
  resource_id?: string;
}

export function useRealtimeEvents(workspaceId: string | null) {
  const queryClient = useQueryClient();
  const [connectionState, setConnectionState] = useState<RealTimeConnectionState>('DISCONNECTED');
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const retryCountRef = useRef(0);

  useEffect(() => {
    if (!workspaceId) {
      setConnectionState('DISCONNECTED');
      cleanup();
      return;
    }

    let isMounted = true;

    const connect = async () => {
      try {
        setConnectionState(retryCountRef.current === 0 ? 'CONNECTING' : 'RECONNECTING');
        
        // Obtain ticket for SSE auth
        const { data } = await apiClient.get<{ ticket: string }>('/auth/events-ticket');
        const ticket = data.ticket;
        
        if (!isMounted) return;

        // Construct SSE URL with ticket
        const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
        const url = `${baseURL}/workspaces/${workspaceId}/events/stream?ticket=${ticket}`;
        
        const es = new EventSource(url, { withCredentials: true });
        eventSourceRef.current = es;

        es.onopen = () => {
          if (isMounted) {
            setConnectionState('CONNECTED');
            retryCountRef.current = 0; // Reset retries on success
          }
        };

        es.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const payload: RealTimeEvent = JSON.parse(event.data);
            handleEvent(payload);
          } catch (err) {
            console.error('Failed to parse SSE event', err);
          }
        };

        es.onerror = (err) => {
          console.error('SSE connection error', err);
          es.close();
          
          if (!isMounted) return;
          
          // Basic exponential backoff up to ~32s
          retryCountRef.current += 1;
          const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 32000);
          
          setConnectionState('RECONNECTING');
          
          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, delay);
        };
      } catch (err: any) {
        if (!isMounted) return;
        console.error('Failed to obtain SSE ticket', err);
        if (err.response?.status === 401 || err.response?.status === 403) {
          setConnectionState('UNAUTHORIZED');
          // Do not retry indefinitely on auth failures
        } else {
          setConnectionState('RECONNECTING');
          retryCountRef.current += 1;
          const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 32000);
          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, delay);
        }
      }
    };

    connect();

    return () => {
      isMounted = false;
      cleanup();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspaceId]);

  const cleanup = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (reconnectTimeoutRef.current !== null) {
      window.clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
  };

  const handleEvent = (event: RealTimeEvent) => {
    if (!workspaceId) return;

    // Show alert in console or relying on a custom hook later if needed
    if (event.event_type === 'THREAT_DETECTED' || event.severity === 'CRITICAL' || event.severity === 'HIGH') {
      console.warn(`[THREAT DETECTED] ${event.title}: ${event.message}`);
    } else {
      console.info(`[EVENT] ${event.title}`);
    }

    // Invalidate relevant queries based on event type
    switch (event.event_type) {
      case 'ANALYSIS_COMPLETED':
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceStats(workspaceId) });
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceEmails(workspaceId) });
        break;
      case 'THREAT_DETECTED':
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceStats(workspaceId) });
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceEmails(workspaceId) });
        break;
      case 'IOC_CREATED':
        queryClient.invalidateQueries({ queryKey: queryKeys.threatIntelligence(workspaceId) });
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceStats(workspaceId) });
        break;
      case 'CAMPAIGN_UPDATED':
        queryClient.invalidateQueries({ queryKey: queryKeys.workspaceCampaigns(workspaceId) });
        // Can't easily invalidate specific params for graph, but could invalidate base key
        queryClient.invalidateQueries({ queryKey: ['campaignGraph', workspaceId] });
        break;
    }
  };

  return { connectionState };
}
