"""Framework middleware for automatic SOCWarden request context capture.

Provides middleware for Flask, Django, and FastAPI/Starlette that
automatically attaches IP, User-Agent, method, and path to every event
sent during a request.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .client import SOCWarden

logger = logging.getLogger("socwarden")

SDK_NAME = "socwarden-python"
SDK_VERSION = "1.0.0"


# ======================================================================
# Flask middleware
# ======================================================================


class SOCWardenFlask:
    """Flask middleware that captures request context for SOCWarden events.

    Usage::

        from flask import Flask
        from socwarden import SOCWarden
        from socwarden.middleware import SOCWardenFlask

        app = Flask(__name__)
        soc = SOCWarden(api_key="sk_...")
        SOCWardenFlask(app, soc)

    After installation, ``soc.track()`` calls made during a request will
    automatically include the request IP and User-Agent in context.
    """

    def __init__(self, app: Any, client: SOCWarden) -> None:
        self._client = client
        self._app = app
        app.before_request(self._before_request)

    def _before_request(self) -> None:
        try:
            from flask import request as flask_request

            _request_context.ip = (
                flask_request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or flask_request.remote_addr
            )
            _request_context.user_agent = flask_request.headers.get("User-Agent", "")
            _request_context.method = flask_request.method
            _request_context.path = flask_request.path
            _request_context.query_string = flask_request.query_string.decode("utf-8", errors="replace")
            _request_context.referer = flask_request.headers.get("Referer", "")
            _request_context.origin = flask_request.headers.get("Origin", "")
            _request_context.content_type = flask_request.headers.get("Content-Type", "")
            _request_context.accept_language = flask_request.headers.get("Accept-Language", "")
            _request_context.request_id = (
                flask_request.headers.get("X-Request-ID", "")
                or flask_request.headers.get("X-Correlation-ID", "")
            )
            # D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
            # allows any client to spoof server-side metadata.
        except Exception:
            logger.debug("SOCWarden: failed to capture Flask request context")


# ======================================================================
# Django middleware
# ======================================================================


class SOCWardenDjangoMiddleware:
    """Django middleware that captures request context for SOCWarden events.

    Add to ``settings.py``::

        MIDDLEWARE = [
            "socwarden.middleware.SOCWardenDjangoMiddleware",
            # ...
        ]

        SOCWARDEN_CLIENT = SOCWarden(api_key="sk_...")

    Or configure via Django settings::

        SOCWARDEN_API_KEY = "sk_..."
        SOCWARDEN_ENDPOINT = "https://ingestor.socwarden.com"
    """

    def __init__(self, get_response: Callable[..., Any]) -> None:
        self.get_response = get_response
        self._client: SOCWarden | None = None

    def _get_client(self) -> SOCWarden | None:
        """Lazily resolve the SOCWarden client from Django settings."""
        if self._client is not None:
            return self._client

        try:
            from django.conf import settings

            # Option 1: pre-configured client instance
            if hasattr(settings, "SOCWARDEN_CLIENT"):
                self._client = settings.SOCWARDEN_CLIENT
                return self._client

            # Option 2: create from settings
            api_key = getattr(settings, "SOCWARDEN_API_KEY", None)
            if api_key:
                from .client import SOCWarden as SOCWardenClient

                self._client = SOCWardenClient(
                    api_key=api_key,
                    endpoint=getattr(settings, "SOCWARDEN_ENDPOINT", "https://ingestor.socwarden.com"),
                )
                return self._client
        except Exception:
            logger.debug("SOCWarden: failed to resolve Django client")

        return None

    def __call__(self, request: Any) -> Any:
        # Capture request context
        _request_context.ip = self._get_client_ip(request)
        _request_context.user_agent = request.META.get("HTTP_USER_AGENT", "")
        _request_context.method = request.method
        _request_context.path = request.path
        _request_context.query_string = request.META.get("QUERY_STRING", "")
        _request_context.referer = request.META.get("HTTP_REFERER", "")
        _request_context.origin = request.META.get("HTTP_ORIGIN", "")
        _request_context.content_type = request.META.get("CONTENT_TYPE", "")
        _request_context.accept_language = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
        _request_context.request_id = (
            request.META.get("HTTP_X_REQUEST_ID", "")
            or request.META.get("HTTP_X_CORRELATION_ID", "")
        )
        # D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
        # allows any client to spoof server-side metadata.

        response = self.get_response(request)

        # Clear context after request
        _request_context.clear()

        return response

    @staticmethod
    def _get_client_ip(request: Any) -> str:
        """Extract client IP respecting X-Forwarded-For."""
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")


# ======================================================================
# FastAPI / Starlette ASGI middleware
# ======================================================================


class SOCWardenASGIMiddleware:
    """ASGI middleware for FastAPI / Starlette.

    Usage::

        from fastapi import FastAPI
        from socwarden import SOCWarden
        from socwarden.middleware import SOCWardenASGIMiddleware

        app = FastAPI()
        soc = SOCWarden(api_key="sk_...")
        app.add_middleware(SOCWardenASGIMiddleware, client=soc)
    """

    def __init__(self, app: Any, client: SOCWarden) -> None:
        self.app = app
        self._client = client

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Extract headers
        headers: dict[str, str] = {}
        for key, value in scope.get("headers", []):
            headers[key.decode("latin-1").lower()] = value.decode("latin-1")

        # Extract client IP
        client = scope.get("client")
        ip = ""
        xff = headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
        elif client:
            ip = client[0]

        # Set request context
        _request_context.ip = ip
        _request_context.user_agent = headers.get("user-agent", "")
        _request_context.method = scope.get("method", "")
        _request_context.path = scope.get("path", "")
        _request_context.query_string = (scope.get("query_string", b"") or b"").decode(
            "utf-8", errors="replace"
        )
        _request_context.referer = headers.get("referer", "")
        _request_context.origin = headers.get("origin", "")
        _request_context.content_type = headers.get("content-type", "")
        _request_context.accept_language = headers.get("accept-language", "")
        _request_context.request_id = (
            headers.get("x-request-id", "") or headers.get("x-correlation-id", "")
        )
        # D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
        # allows any client to spoof server-side metadata.

        try:
            await self.app(scope, receive, send)
        finally:
            _request_context.clear()


# ======================================================================
# Thread-local request context
# ======================================================================


class _RequestContext(object):
    """Thread-local storage for request context captured by middleware.

    This allows ``SOCWarden.track()`` to automatically include request
    information without the caller having to pass it explicitly.
    """

    def __init__(self) -> None:
        import threading

        self._local = threading.local()

    @property
    def ip(self) -> str:
        return getattr(self._local, "ip", "")

    @ip.setter
    def ip(self, value: str) -> None:
        self._local.ip = value

    @property
    def user_agent(self) -> str:
        return getattr(self._local, "user_agent", "")

    @user_agent.setter
    def user_agent(self, value: str) -> None:
        self._local.user_agent = value

    @property
    def method(self) -> str:
        return getattr(self._local, "method", "")

    @method.setter
    def method(self, value: str) -> None:
        self._local.method = value

    @property
    def path(self) -> str:
        return getattr(self._local, "path", "")

    @path.setter
    def path(self, value: str) -> None:
        self._local.path = value

    @property
    def query_string(self) -> str:
        return getattr(self._local, "query_string", "")

    @query_string.setter
    def query_string(self, value: str) -> None:
        self._local.query_string = value

    @property
    def referer(self) -> str:
        return getattr(self._local, "referer", "")

    @referer.setter
    def referer(self, value: str) -> None:
        self._local.referer = value

    @property
    def origin(self) -> str:
        return getattr(self._local, "origin", "")

    @origin.setter
    def origin(self, value: str) -> None:
        self._local.origin = value

    @property
    def content_type(self) -> str:
        return getattr(self._local, "content_type", "")

    @content_type.setter
    def content_type(self, value: str) -> None:
        self._local.content_type = value

    @property
    def accept_language(self) -> str:
        return getattr(self._local, "accept_language", "")

    @accept_language.setter
    def accept_language(self, value: str) -> None:
        self._local.accept_language = value

    @property
    def request_id(self) -> str:
        return getattr(self._local, "request_id", "")

    @request_id.setter
    def request_id(self, value: str) -> None:
        self._local.request_id = value

    @property
    def browser_context(self) -> str:
        return getattr(self._local, "browser_context", "")

    @browser_context.setter
    def browser_context(self, value: str) -> None:
        self._local.browser_context = value

    def clear(self) -> None:
        """Reset all context fields."""
        self._local.ip = ""
        self._local.user_agent = ""
        self._local.method = ""
        self._local.path = ""
        self._local.query_string = ""
        self._local.referer = ""
        self._local.origin = ""
        self._local.content_type = ""
        self._local.accept_language = ""
        self._local.request_id = ""
        self._local.browser_context = ""

    def to_dict(self) -> dict[str, str]:
        """Return non-empty context fields as a dict."""
        ctx: dict[str, str] = {}
        if self.ip:
            ctx["ip"] = self.ip
        if self.user_agent:
            ctx["user_agent"] = self.user_agent
        if self.method:
            ctx["method"] = self.method
        if self.path:
            ctx["path"] = self.path
        if self.query_string:
            ctx["query_string"] = self.query_string
        if self.referer:
            ctx["referer"] = self.referer
        if self.origin:
            ctx["origin"] = self.origin
        if self.content_type:
            ctx["content_type"] = self.content_type
        if self.accept_language:
            ctx["accept_language"] = self.accept_language
        if self.request_id:
            ctx["request_id"] = self.request_id
        if self.browser_context:
            ctx["browser_context"] = self.browser_context
        return ctx


# Singleton for cross-module access
_request_context = _RequestContext()


def get_request_context() -> _RequestContext:
    """Return the global request context (used internally by the client)."""
    return _request_context
