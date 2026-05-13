const SESSION_STORAGE_KEY = 'session_id';
const LEGACY_SESSION_STORAGE_KEY = 'phishshield_session_id';
const LIVE_FEED_STORAGE_PREFIX = 'phishshield_live_feed';

export function getSessionId() {
  if (typeof window === 'undefined') {
    return 'server-session';
  }

  const existing = window.localStorage.getItem(SESSION_STORAGE_KEY) || window.localStorage.getItem(LEGACY_SESSION_STORAGE_KEY);
  if (existing) {
    window.localStorage.setItem(SESSION_STORAGE_KEY, existing);
    window.localStorage.setItem(LEGACY_SESSION_STORAGE_KEY, existing);
    return existing;
  }

  const generated = window.crypto?.randomUUID?.() ?? `session-${Date.now()}`;
  window.localStorage.setItem(SESSION_STORAGE_KEY, generated);
  window.localStorage.setItem(LEGACY_SESSION_STORAGE_KEY, generated);
  return generated;
}

export function getLiveFeedStorageKey(sessionId: string) {
  return `${LIVE_FEED_STORAGE_PREFIX}_${sessionId}`;
}