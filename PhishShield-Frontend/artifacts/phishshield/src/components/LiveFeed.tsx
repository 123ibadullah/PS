import { useEffect, useMemo, useRef, useState } from 'react';
import { getSessionId } from '@/lib/session';

interface ScanEvent {
  type: string;
  scan_id?: string;
  session_id?: string;
  verdict?: string;
  risk_score?: number;
  category?: string;
  sender_domain?: string;
  timestamp?: string;
  language?: string;
}

interface LocalHistoryItem {
  id?: string;
  timestamp?: string;
  emailPreview?: string;
  riskScore?: number;
  classification?: string;
  detectedLanguage?: string;
}

const VERDICT_COLOR: Record<string, string> = {
  'High Risk': 'text-red-600',
  Suspicious: 'text-yellow-600',
  Safe: 'text-green-600',
};

const BACKEND_URL = (import.meta.env.VITE_BACKEND_URL as string | undefined)?.trim() || 'http://localhost:8000';
const LIVE_FEED_STORAGE_PREFIX = 'phishshield_live_feed';

function getLiveFeedStorageKey(sessionId: string) {
  return `${LIVE_FEED_STORAGE_PREFIX}_${sessionId}`;
}

function loadStoredLiveFeedEvents(sessionId: string): ScanEvent[] {
  if (typeof window === 'undefined') {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(getLiveFeedStorageKey(sessionId));
    if (!raw) return [];

    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter((item): item is ScanEvent => Boolean(item && typeof item === 'object'))
      : [];
  } catch {
    return [];
  }
}

function normalizeVerdictFromHistory(classification?: string) {
  if (classification === 'phishing') return 'High Risk';
  if (classification === 'safe') return 'Safe';
  return 'Suspicious';
}

function loadLocalHistoryEvents(): ScanEvent[] {
  if (typeof window === 'undefined') {
    return [];
  }

  try {
    const raw = window.localStorage.getItem('phishshield_history');
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    return (parsed as LocalHistoryItem[]).map((item) => ({
      type: 'scan_complete',
      scan_id: item.id,
      verdict: normalizeVerdictFromHistory(item.classification),
      risk_score: Number(item.riskScore ?? 0),
      sender_domain: item.emailPreview,
      timestamp: item.timestamp,
      language: item.detectedLanguage,
    }));
  } catch {
    return [];
  }
}

function mergeEvents(...groups: ScanEvent[][]): ScanEvent[] {
  const byKey = new Map<string, ScanEvent>();

  const scoreEvent = (event: ScanEvent) => {
    let score = 0;
    if (event.scan_id) score += 1000;
    if (event.verdict) score += 50;
    if (event.risk_score !== undefined) score += 25;
    if (event.sender_domain) score += 20;
    if (event.timestamp) score += 10;
    if (event.language) score += 5;
    return score;
  };

  for (const group of groups) {
    for (const event of group) {
      const key = event.scan_id || `${event.timestamp ?? ''}|${event.sender_domain ?? ''}|${event.risk_score ?? ''}`;
      const existing = byKey.get(key);
      if (!existing || scoreEvent(event) >= scoreEvent(existing)) {
        byKey.set(key, event);
      }
    }
  }

  return Array.from(byKey.values())
    .sort((a, b) => (Date.parse(b.timestamp ?? '') || 0) - (Date.parse(a.timestamp ?? '') || 0))
    .slice(0, 50);
}

function dedupeByScanId(events: ScanEvent[]): ScanEvent[] {
  const seenIds = new Set<string>();
  const finalEvents: ScanEvent[] = [];

  for (const event of events) {
    if (event.scan_id) {
      if (seenIds.has(event.scan_id)) {
        continue;
      }
      seenIds.add(event.scan_id);
    }
    
    // Also content-based dedupe for legacy bad data
    if (isDuplicateScanContent(event, finalEvents)) {
      continue;
    }

    finalEvents.push(event);
  }

  return finalEvents;
}

function isDuplicateScanContent(nextEvent: ScanEvent, existingEvents: ScanEvent[]): boolean {
  const nextTimestamp = Date.parse(nextEvent.timestamp ?? '');
  if (!Number.isFinite(nextTimestamp)) {
    return false;
  }

  return existingEvents.some((existingEvent) => {
    const existingTimestamp = Date.parse(existingEvent.timestamp ?? '');
    if (!Number.isFinite(existingTimestamp)) {
      return false;
    }

    return (
      existingEvent.verdict === nextEvent.verdict
      && Number(existingEvent.risk_score ?? -1) === Number(nextEvent.risk_score ?? -1)
      && Math.abs(existingTimestamp - nextTimestamp) <= 2000
    );
  });
}

export default function LiveFeed() {
  const sessionId = useMemo(() => getSessionId(), []);
  const initialEvents = useMemo(() => loadStoredLiveFeedEvents(sessionId), [sessionId]);
  const [events, setEvents] = useState<ScanEvent[]>(() => initialEvents);
  const [connected, setConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(false);
  const hydratedRef = useRef(initialEvents.length > 0);

  useEffect(() => {
    mountedRef.current = true;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectDelay = 2000;

    const socketUrl = new URL('ws://localhost:8000/ws/feed');
    socketUrl.searchParams.set('session_id', sessionId);

    const handleBeforeUnload = () => {
      const socket = socketRef.current;
      if (socket && socket.readyState !== WebSocket.CLOSED) {
        try { socket.close(1000, 'Page unloading'); } catch { /* ignore */ }
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);

    const scheduleReconnect = () => {
      if (!mountedRef.current) return;
      reconnectTimer = setTimeout(() => {
        if (mountedRef.current) connectSocket();
      }, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 1.5, 30_000);
    };

    const connectSocket = () => {
      const existing = socketRef.current;
      if (existing && (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)) {
        return;
      }

      if (existing && existing.readyState !== WebSocket.CLOSED) {
        try { existing.close(1000, 'Replacing stale socket'); } catch { /* ignore */ }
      }

      const socket = new WebSocket(socketUrl.toString());
      socketRef.current = socket;

      socket.onopen = () => {
        if (socket !== socketRef.current) return;
        reconnectDelay = 2000;
        if (mountedRef.current) setConnected(true);
      };

      socket.onmessage = (event: MessageEvent) => {
        if (socket !== socketRef.current) return;
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'ping') {
            try { socket.send(JSON.stringify({ type: 'pong', session_id: sessionId })); } catch { /* ignore */ }
            return;
          }
          if (data.type === 'pong' || data.type === 'connected') return;
          if (data.type === 'scan_complete' && mountedRef.current) {
            hydratedRef.current = true;
            setEvents((prev) => {
              if (data.scan_id && prev.some((ev) => ev.scan_id === data.scan_id)) return prev;
              if (isDuplicateScanContent(data, prev)) return prev;
              return mergeEvents([data], prev);
            });
          }
        } catch { /* ignore */ }
      };

      socket.onerror = () => {
        // onerror always precedes onclose - let onclose handle state
      };

      socket.onclose = (event: CloseEvent) => {
        if (socket !== socketRef.current) return;
        socketRef.current = null;
        if (mountedRef.current) {
          setConnected(false);
          if (event.code !== 1000) scheduleReconnect();
        }
      };
    };

    const loadEvents = async () => {
      try {
        const localHistoryEvents = loadLocalHistoryEvents();
        const cachedEvents = loadStoredLiveFeedEvents(sessionId);

        const recentResponse = await fetch(`${BACKEND_URL}/recent-scans?session_id=${encodeURIComponent(sessionId)}`);
        if (!mountedRef.current || !recentResponse.ok) {
          const mergedLocalOnly = mergeEvents(cachedEvents, localHistoryEvents);
          if (mergedLocalOnly.length > 0) {
            hydratedRef.current = true;
            setEvents(dedupeByScanId(mergedLocalOnly));
          }
          return;
        }

        const recent: Array<Omit<ScanEvent, 'type'> & { scan_id?: string }> = await recentResponse.json();
        const hydratedEvents = recent.map((scan) => ({
          type: 'scan_complete',
          scan_id: scan.scan_id,
          session_id: scan.session_id,
          verdict: scan.verdict,
          risk_score: scan.risk_score,
          sender_domain: scan.sender_domain,
          timestamp: scan.timestamp,
          language: scan.language,
        }));

        if (hydratedEvents.length > 0) {
          hydratedRef.current = true;
          setEvents(dedupeByScanId(mergeEvents(hydratedEvents, cachedEvents, localHistoryEvents)));
          return;
        }

        const historyResponse = await fetch(`${BACKEND_URL}/api/history?session_id=${encodeURIComponent(sessionId)}`);
        if (!mountedRef.current || !historyResponse.ok) {
          return;
        }

        const history: Array<{ id?: string; timestamp?: string; emailPreview?: string; riskScore?: number; classification?: string; detectedLanguage?: string }> = await historyResponse.json();
        const hydratedHistoryEvents = history.map((item) => ({
          type: 'scan_complete',
          scan_id: item.id,
          verdict: item.classification === 'safe' ? 'Safe' : item.classification === 'phishing' ? 'High Risk' : 'Suspicious',
          risk_score: item.riskScore,
          sender_domain: item.emailPreview,
          timestamp: item.timestamp,
          language: item.detectedLanguage,
        }));
        if (hydratedHistoryEvents.length > 0) {
          hydratedRef.current = true;
          setEvents(dedupeByScanId(mergeEvents(hydratedHistoryEvents, cachedEvents, localHistoryEvents)));
          return;
        }

        const mergedFallbackEvents = mergeEvents(cachedEvents, localHistoryEvents);
        if (mergedFallbackEvents.length > 0) {
          hydratedRef.current = true;
          setEvents(dedupeByScanId(mergedFallbackEvents));
        }
      } catch {
        // Best effort hydration.
      }
    };

    void (async () => {
      await loadEvents();
      if (mountedRef.current) {
        connectSocket();
      }
    })();

    return () => {
      mountedRef.current = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);

      window.removeEventListener('beforeunload', handleBeforeUnload);

      const socket = socketRef.current;
      socketRef.current = null;

      if (socket && socket.readyState !== WebSocket.CLOSED) {
        try { socket.close(1000, 'LiveFeed unmounted'); } catch { /* ignore */ }
      }
    };
  }, [sessionId]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    if (!hydratedRef.current) {
      return;
    }

    try {
      window.localStorage.setItem(getLiveFeedStorageKey(sessionId), JSON.stringify(events));
    } catch {
      // Ignore persistence failures.
    }
  }, [events, sessionId]);

  const statusText = useMemo(() => (connected ? 'Live Feed Active' : 'Disconnected'), [connected]);

  return (
    <div className="p-4 border rounded-lg bg-gray-900 text-white max-h-96 overflow-y-auto">
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
        <span className="text-sm font-mono">{statusText}</span>
        <span className="ml-auto text-xs text-gray-400">{events.length} events</span>
      </div>
      {events.length === 0 && (
        <p className="text-gray-500 text-sm text-center py-8">Waiting for scans...</p>
      )}
      {events.map((ev, i) => (
        <div key={`${ev.scan_id ?? 'scan'}-${ev.timestamp ?? i}-${i}`} className="flex items-center gap-3 py-2 border-b border-gray-800 text-sm font-mono">
          <span className="text-gray-500 text-xs w-20 shrink-0">
            {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ''}
          </span>
          <span className={`font-bold w-20 shrink-0 ${VERDICT_COLOR[ev.verdict || ''] || 'text-gray-400'}`}>
            {ev.verdict}
          </span>
          <span className="text-gray-300 w-8 shrink-0">{ev.risk_score}</span>
          <span className="text-gray-400 truncate">{ev.sender_domain || ev.category}</span>
          <span className="text-gray-600 text-xs shrink-0">{ev.language}</span>
        </div>
      ))}
    </div>
  );
}
