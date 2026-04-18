let socket = null;
let socketSessionId = null;

export function getSocket(sessionId) {
  const normalizedSessionId = sessionId || 'anonymous-session';
  const socketUrl = new URL('ws://localhost:8000/ws/feed');
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