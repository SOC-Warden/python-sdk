"""SOCWarden Python SDK client."""

from __future__ import annotations

import ipaddress
import logging
import re
import os
import platform
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import httpx

from .types import EventPayload, HasEmail, HasIdentity, HasPK

logger = logging.getLogger("socwarden")

SDK_NAME = "socwarden-python"
SDK_VERSION = "1.0.0"

# D3 FIX: Event type validation regex — matches the ingestor's required format.
_EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$")


class SOCWarden:
    """Client for sending security events to the SOCWarden ingestor.

    Events are sent asynchronously in a background thread pool so that
    ``track()`` never blocks the caller.

    Args:
        api_key: Bearer token for the ingestor API.
        endpoint: Base URL of the ingestor (no trailing slash).
        timeout: HTTP request timeout in seconds.
        max_workers: Size of the background thread pool.
        auto_context: Attach server/SDK context to every event.
    """

    def __init__(
        self,
        api_key: str,
        endpoint: str = "https://ingest.socwarden.com",
        *,
        timeout: float = 5.0,
        max_workers: int = 4,
        auto_context: bool = True,
    ) -> None:
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")

        # D2 FIX: Enforce HTTPS to prevent API key transmission in cleartext.
        if not self._endpoint.startswith("https://"):
            import os
            if os.environ.get("SOCWARDEN_ENV", "").lower() == "production" or os.environ.get("ENV", "").lower() == "production":
                raise ValueError(
                    "[SOCWarden] Endpoint must use HTTPS in production. "
                    "API keys must not be transmitted in cleartext."
                )
            logger.warning(
                "[SOCWarden] WARNING: Endpoint is using HTTP. API keys will be transmitted in cleartext."
            )
        self._timeout = timeout
        self._auto_context = auto_context

        # 429 back-off state (thread-safe)
        self._lock = threading.Lock()
        self._backoff_until: float = 0.0
        self._backoff_duration: int = 3600  # 1 hour default
        self._probe_interval: int = 300  # 5 min probe
        self._last_probe: float = 0.0

        # Background sender
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="socwarden",
        )

        # Reusable HTTP client
        self._http = httpx.Client(
            base_url=self._endpoint,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"{SDK_NAME}/{SDK_VERSION}",
            },
            timeout=self._timeout,
        )

        # Async HTTP client (created lazily)
        self._async_http: httpx.AsyncClient | None = None
        self._async_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track(
        self,
        event: str,
        *,
        actor: Any = None,
        actor_id: str | None = None,
        actor_email: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | str | None = None,
        resource: Any = None,
        resource_id: str | int | None = None,
    ) -> None:
        """Track an event with named arguments.

        Sends the event asynchronously in a background thread so this
        method returns immediately.

        Args:
            event: Dot-separated event type (e.g. ``auth.login.success``).
            actor: User object (reads ``.id`` / ``.pk`` and ``.email``) or string ID.
            actor_id: Explicit actor ID (overrides ``actor``).
            actor_email: Explicit actor email (overrides ``actor``).
            ip: Source IP address.
            user_agent: User-Agent string.
            metadata: Arbitrary key-value metadata dict.
            timestamp: Event time as datetime or ISO 8601 string.
            resource: Resource object (reads class name + ``.pk`` / ``.id``) or type string.
            resource_id: Explicit resource ID (used when ``resource`` is a string).
        """
        # D3 FIX: Validate event type format before sending.
        if not _EVENT_TYPE_RE.match(event):
            logger.warning(
                "SOCWarden: invalid event type format, dropping event: %r. "
                "Event types must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$",
                event,
            )
            return
        data = self._resolve_args(
            actor=actor,
            actor_id=actor_id,
            actor_email=actor_email,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
            timestamp=timestamp,
            resource=resource,
            resource_id=resource_id,
        )
        payload = self._build_payload(event, data)
        self._executor.submit(self._send, payload)

    def track_data(self, event: str, data: dict[str, Any] | None = None) -> None:
        """Track an event with a raw data dict.

        Args:
            event: Dot-separated event type.
            data: Raw data dict matching the ingestor schema.
        """
        # D3 FIX: Validate event type format before sending.
        if not _EVENT_TYPE_RE.match(event):
            logger.warning(
                "SOCWarden: invalid event type format, dropping event: %r. "
                "Event types must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$",
                event,
            )
            return
        payload = self._build_payload(event, data or {})
        self._executor.submit(self._send, payload)

    async def track_async(
        self,
        event: str,
        *,
        actor: Any = None,
        actor_id: str | None = None,
        actor_email: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | str | None = None,
        resource: Any = None,
        resource_id: str | int | None = None,
    ) -> None:
        """Async version of :meth:`track` for asyncio applications.

        Sends the event using an async HTTP client without blocking the
        event loop.
        """
        # D3 FIX: Validate event type format before sending.
        if not _EVENT_TYPE_RE.match(event):
            logger.warning(
                "SOCWarden: invalid event type format, dropping event: %r. "
                "Event types must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$",
                event,
            )
            return
        data = self._resolve_args(
            actor=actor,
            actor_id=actor_id,
            actor_email=actor_email,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
            timestamp=timestamp,
            resource=resource,
            resource_id=resource_id,
        )
        payload = self._build_payload(event, data)
        await self._send_async(payload)

    def event(self, name: str) -> "EventBuilder":
        """Start building an event with the fluent API.

        Example::

            soc.event("data.exported") \\
                .actor(user) \\
                .resource("Report", report_id) \\
                .meta("format", "csv") \\
                .send()
        """
        from .builder import EventBuilder

        return EventBuilder(name, self)

    def close(self) -> None:
        """Shut down the background thread pool and HTTP client.

        Waits for pending events to be sent before returning.
        """
        self._executor.shutdown(wait=True)
        self._http.close()
        if self._async_http is not None:
            # Async client must be closed in an async context; best-effort
            try:
                import asyncio

                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._async_http.aclose())
                else:
                    loop.run_until_complete(self._async_http.aclose())
            except Exception:
                pass

    def __enter__(self) -> "SOCWarden":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Argument resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_args(
        *,
        actor: Any = None,
        actor_id: str | None = None,
        actor_email: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | str | None = None,
        resource: Any = None,
        resource_id: str | int | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}

        # Actor: object with .id/.pk and .email, or plain string
        if actor is not None:
            if isinstance(actor, str):
                data["actor_id"] = actor
            else:
                # Try .pk first (Django), then .id
                if isinstance(actor, HasPK):
                    data["actor_id"] = str(actor.pk)
                elif isinstance(actor, HasIdentity):
                    data["actor_id"] = str(actor.id)
                if isinstance(actor, HasEmail):
                    data["actor_email"] = actor.email

        # Explicit scalars override model-derived values
        if actor_id is not None:
            data["actor_id"] = actor_id
        if actor_email is not None:
            data["actor_email"] = actor_email
        if ip is not None:
            clean_ip = SOCWarden._sanitize_ip(ip)
            if clean_ip is not None:
                data["ip"] = clean_ip
        if user_agent is not None:
            data["user_agent"] = user_agent
        if metadata is not None:
            data["metadata"] = metadata

        # Timestamp
        if timestamp is not None:
            if isinstance(timestamp, datetime):
                data["timestamp"] = timestamp.isoformat()
            else:
                data["timestamp"] = timestamp

        # Resource: object (reads class name + pk/id) or string type
        if resource is not None:
            data.setdefault("metadata", {})
            if isinstance(resource, str):
                data["metadata"]["resource_type"] = resource
                if resource_id is not None:
                    data["metadata"]["resource_id"] = str(resource_id)
            else:
                data["metadata"]["resource_type"] = type(resource).__name__
                if isinstance(resource, HasPK):
                    data["metadata"]["resource_id"] = str(resource.pk)
                elif isinstance(resource, HasIdentity):
                    data["metadata"]["resource_id"] = str(resource.id)

        # Strip None values
        return {k: v for k, v in data.items() if v is not None}

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    def _build_payload(self, event: str, data: dict[str, Any]) -> EventPayload:
        payload: dict[str, Any] = {
            "event": event,
            "source": "sdk",
        }

        for field in ("actor_id", "actor_email", "user_agent", "metadata", "timestamp"):
            if field in data:
                payload[field] = data[field]
        if "ip" in data and data["ip"]:
            payload["ip"] = data["ip"]

        if self._auto_context:
            payload["context"] = self._collect_context()

        return payload  # type: ignore[return-value]

    @staticmethod
    def _collect_context() -> dict[str, Any]:
        from .middleware import get_request_context

        context: dict[str, Any] = {
            "sdk": {
                "name": SDK_NAME,
                "version": SDK_VERSION,
            },
            "server": {
                "hostname": platform.node(),
                "runtime": f"Python {platform.python_version()}",
                "pid": os.getpid(),
            },
        }

        req_ctx = get_request_context()
        req_dict: dict[str, Any] = {}
        if req_ctx.method:
            req_dict["method"] = req_ctx.method
        if req_ctx.path:
            req_dict["path"] = req_ctx.path
        if req_ctx.query_string:
            req_dict["query_string"] = SOCWarden._sanitize_query_string(req_ctx.query_string)
        if req_ctx.referer:
            req_dict["referer"] = req_ctx.referer
        if req_ctx.origin:
            req_dict["origin"] = req_ctx.origin
        if req_ctx.content_type:
            req_dict["content_type"] = req_ctx.content_type
        if req_ctx.accept_language:
            req_dict["accept_language"] = req_ctx.accept_language
        if req_ctx.request_id:
            req_dict["request_id"] = req_ctx.request_id
        if req_ctx.ip:
            req_dict["ip"] = req_ctx.ip
        if req_ctx.user_agent:
            req_dict["user_agent"] = req_ctx.user_agent

        if req_dict:
            context["request"] = req_dict

        # D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
        # allows any client to spoof server-side metadata. Browser context from
        # incoming request headers is no longer merged into server-side context.

        return context

    @staticmethod
    def _sanitize_ip(ip: str | None) -> str | None:
        """Return ip if it's a valid IPv4/IPv6 address, otherwise None.

        Matches the ingestor's validate:"omitempty,ip" constraint.
        """
        if not ip:
            return None
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None

    @staticmethod
    def _sanitize_query_string(qs: str) -> str:
        """Redact sensitive parameter values from a query string.

        Parameters whose names contain any of the sensitive keywords have
        their values replaced with ``[REDACTED]``.  Mirrors the Laravel SDK
        sanitization behaviour.
        """
        if not qs:
            return ""

        sensitive = ("token", "key", "password", "secret", "code", "auth", "session", "csrf")
        parts: list[str] = []
        for pair in qs.split("&"):
            kv = pair.split("=", 1)
            param_name = kv[0].lower()
            if len(kv) == 2 and any(s in param_name for s in sensitive):
                parts.append(f"{kv[0]}=[REDACTED]")
            else:
                parts.append(pair)
        return "&".join(parts)

    # ------------------------------------------------------------------
    # HTTP transport
    # ------------------------------------------------------------------

    def _send(self, payload: EventPayload) -> dict[str, Any] | None:
        """Send a payload to the ingestor (synchronous, thread-safe)."""
        with self._lock:
            now = time.monotonic()

            # Check 429 backoff
            if now < self._backoff_until:
                if now - self._last_probe < self._probe_interval:
                    logger.debug("SOCWarden: in backoff, skipping event")
                    return None
                self._last_probe = now

        try:
            response = self._http.post("/v1/events", json=payload)
        except httpx.HTTPError as exc:
            logger.warning("SOCWarden: failed to send event: %s", exc)
            return None

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", self._backoff_duration))
            with self._lock:
                self._backoff_until = time.monotonic() + retry_after
            logger.warning("SOCWarden: quota exceeded (429). Backing off for %ds", retry_after)
            return None

        if response.status_code >= 400:
            logger.warning(
                "SOCWarden: event send failed (status=%d): %s",
                response.status_code,
                response.text,
            )
            return None

        # Clear backoff on success
        with self._lock:
            if self._backoff_until > 0:
                self._backoff_until = 0.0
                self._last_probe = 0.0
                logger.info("SOCWarden: quota restored, backoff cleared")

        return response.json()

    async def _send_async(self, payload: EventPayload) -> dict[str, Any] | None:
        """Send a payload to the ingestor (async)."""
        client = self._get_async_client()

        with self._lock:
            now = time.monotonic()
            if now < self._backoff_until:
                if now - self._last_probe < self._probe_interval:
                    logger.debug("SOCWarden: in backoff, skipping event")
                    return None
                self._last_probe = now

        try:
            response = await client.post("/v1/events", json=payload)
        except httpx.HTTPError as exc:
            logger.warning("SOCWarden: failed to send event: %s", exc)
            return None

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", self._backoff_duration))
            with self._lock:
                self._backoff_until = time.monotonic() + retry_after
            logger.warning("SOCWarden: quota exceeded (429). Backing off for %ds", retry_after)
            return None

        if response.status_code >= 400:
            logger.warning(
                "SOCWarden: event send failed (status=%d): %s",
                response.status_code,
                response.text,
            )
            return None

        with self._lock:
            if self._backoff_until > 0:
                self._backoff_until = 0.0
                self._last_probe = 0.0
                logger.info("SOCWarden: quota restored, backoff cleared")

        return response.json()

    def _get_async_client(self) -> httpx.AsyncClient:
        """Lazily create the async HTTP client."""
        if self._async_http is None:
            with self._async_lock:
                if self._async_http is None:
                    self._async_http = httpx.AsyncClient(
                        base_url=self._endpoint,
                        headers={
                            "Authorization": f"Bearer {self._api_key}",
                            "Content-Type": "application/json",
                            "User-Agent": f"{SDK_NAME}/{SDK_VERSION}",
                        },
                        timeout=self._timeout,
                    )
        return self._async_http
