"""Thread-safe Server-Sent Events broadcast hub with monotonic snapshots."""

from __future__ import annotations

from dataclasses import dataclass
import json
import threading
import time
from typing import Any, BinaryIO, Dict, Optional


@dataclass
class _Subscriber:
    client_id: int
    connected_at: float
    last_version: int = 0
    events_sent: int = 0


class SSEHub:
    """Thread-safe SSE broadcaster keyed by monotonic snapshot version.

    Each HTTP handler thread owns its own socket writer, eliminating concurrent
    frame interleaving while allowing any background or request thread to push
    updated state snapshots to all active listeners.
    """

    def __init__(self, max_clients: int = 128) -> None:
        if max_clients < 1:
            raise ValueError("max_clients must be >= 1")
        self.max_clients = max_clients
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._version = 0
        self._latest_event = "snapshot"
        self._latest_json: Optional[str] = None
        self._latest_frame: Optional[bytes] = None
        self._closed = False
        self._next_client_id = 1
        self._clients: Dict[int, _Subscriber] = {}
        self._total_connected = 0
        self._total_disconnected = 0
        self._events_broadcast = 0

    def publish(
        self,
        payload: Dict[str, Any],
        *,
        event: str = "snapshot",
        only_if_changed: bool = False,
    ) -> int:
        """Publish a state snapshot and wake all connected SSE listeners."""
        encoded_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            if self._closed:
                return self._version
            if only_if_changed and encoded_json == self._latest_json and event == self._latest_event:
                return self._version
            self._version += 1
            version = self._version
            self._latest_event = event
            self._latest_json = encoded_json
            frame = f"id: {version}\nevent: {event}\ndata: {encoded_json}\n\n".encode(
                "utf-8"
            )
            self._latest_frame = frame
            self._cond.notify_all()
            return version

    def close(self) -> None:
        """Signal all active SSE stream loops to terminate cleanly."""
        with self._lock:
            self._closed = True
            self._cond.notify_all()

    def reopen(self) -> None:
        with self._lock:
            self._closed = False

    def stream(
        self,
        writer: BinaryIO,
        *,
        heartbeat_seconds: float = 15.0,
        max_events: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> int:
        """Stream initial snapshot, monotonic updates, and heartbeats until disconnect.

        Returns the number of data events delivered to this subscriber.
        """
        with self._lock:
            if self._closed:
                return 0
            if len(self._clients) >= self.max_clients:
                raise RuntimeError("SSE client capacity reached")
            client_id = self._next_client_id
            self._next_client_id += 1
            sub = _Subscriber(client_id=client_id, connected_at=time.time())
            self._clients[client_id] = sub
            self._total_connected += 1
            initial_frame = self._latest_frame
            initial_version = self._version

        sent = 0
        try:
            if initial_frame is not None:
                writer.write(initial_frame)
                writer.flush()
                sent += 1
                with self._lock:
                    sub.last_version = initial_version
                    sub.events_sent += 1
                    self._events_broadcast += 1
                if max_events is not None and sent >= max_events:
                    return sent

            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                frame_to_send: Optional[bytes] = None
                target_version = sub.last_version
                with self._lock:
                    if self._closed:
                        break
                    if self._version <= sub.last_version:
                        self._cond.wait(timeout=heartbeat_seconds)
                    if self._closed or (stop_event is not None and stop_event.is_set()):
                        break
                    if self._version > sub.last_version and self._latest_frame is not None:
                        frame_to_send = self._latest_frame
                        target_version = self._version

                if frame_to_send is not None:
                    writer.write(frame_to_send)
                    writer.flush()
                    sent += 1
                    with self._lock:
                        sub.last_version = target_version
                        sub.events_sent += 1
                        self._events_broadcast += 1
                    if max_events is not None and sent >= max_events:
                        break
                else:
                    writer.write(b": heartbeat\n\n")
                    writer.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                self._clients.pop(client_id, None)
                self._total_disconnected += 1
        return sent

    def stats(self) -> Dict[str, Any]:
        """Return live connection and broadcast metrics."""
        with self._lock:
            return {
                "version": self._version,
                "connected_clients": len(self._clients),
                "max_clients": self.max_clients,
                "total_connected": self._total_connected,
                "total_disconnected": self._total_disconnected,
                "events_broadcast": self._events_broadcast,
            }
