let socket = null;
let socketSessionId = null;
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000';

export function getSocket(sessionId) {
  const normalizedSessionId = sessionId || 'anonymous-session';
  const socketUrl = new URL('/ws/feed', WS_URL);
  socketUrl.searchParams.set('session_id', normalizedSessionId);

  if (
    !socket ||
    socket.readyState === WebSocket.CLOSED ||
    socket.readyState === WebSocket.CLOSING ||
    socketSessionId !== normalizedSessionId
  ) {
    if (socket && socket.readyState === WebSocket.OPEN && socketSessionId !== normalizedSessionId) {
      socket.close();
    }

    socket = new WebSocket(socketUrl.toString());
    socketSessionId = normalizedSessionId;

    socket.onopen = () => console.log('WS CONNECTED ✅');
    socket.onclose = () => console.log('WS CLOSED ❌');
  }

  return socket;
}