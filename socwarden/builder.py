"""Fluent event builder for SOCWarden."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import SOCWarden


class EventBuilder:
    """Fluent builder for constructing and sending a SOCWarden event.

    Example::

        soc.event("auth.login.success") \\
            .actor(user) \\
            .ip("203.0.113.42") \\
            .meta("mfa", True) \\
            .send()
    """

    def __init__(self, event: str, client: SOCWarden) -> None:
        self._event = event
        self._client = client
        self._data: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Actor
    # ------------------------------------------------------------------

    def actor(self, actor: Any, email: str | None = None) -> EventBuilder:
        """Set the actor (user) who triggered the event.

        Accepts a user object (reads ``.id`` / ``.pk`` and ``.email``),
        a string ID, or a string ID with an explicit email.

        Args:
            actor: User model instance or string ID.
            email: Optional email override.
        """
        if isinstance(actor, str):
            self._data["actor_id"] = actor
            if email is not None:
                self._data["actor_email"] = email
        else:
            # Object: try .pk (Django), then .id
            if hasattr(actor, "pk"):
                self._data["actor_id"] = str(actor.pk)
            elif hasattr(actor, "id"):
                self._data["actor_id"] = str(actor.id)
            # Email from object or override
            if email is not None:
                self._data["actor_email"] = email
            elif hasattr(actor, "email") and actor.email:
                self._data["actor_email"] = actor.email
        return self

    def actor_id(self, id: str) -> EventBuilder:
        """Set the actor ID directly."""
        self._data["actor_id"] = id
        return self

    def actor_email(self, email: str) -> EventBuilder:
        """Set the actor email directly."""
        self._data["actor_email"] = email
        return self

    # ------------------------------------------------------------------
    # Request context
    # ------------------------------------------------------------------

    def ip(self, ip: str) -> EventBuilder:
        """Set the source IP address."""
        self._data["ip"] = ip
        return self

    def user_agent(self, ua: str) -> EventBuilder:
        """Set the User-Agent string."""
        self._data["user_agent"] = ua
        return self

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def metadata(self, data: dict[str, Any]) -> EventBuilder:
        """Merge a dict of metadata into the event.

        Calling this multiple times merges all keys.
        """
        existing = self._data.get("metadata", {})
        existing.update(data)
        self._data["metadata"] = existing
        return self

    def meta(self, key: str, value: Any) -> EventBuilder:
        """Set a single metadata key-value pair."""
        self._data.setdefault("metadata", {})[key] = value
        return self

    # ------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------

    def resource(self, type_or_obj: Any, id: str | int | None = None) -> EventBuilder:
        """Attach the resource that was acted upon.

        Args:
            type_or_obj: A string type name (e.g. ``"Order"``) or a model
                instance whose class name and ``.pk`` / ``.id`` are read.
            id: Explicit resource ID (used when ``type_or_obj`` is a string).
        """
        meta = self._data.setdefault("metadata", {})
        if isinstance(type_or_obj, str):
            meta["resource_type"] = type_or_obj
            if id is not None:
                meta["resource_id"] = str(id)
        else:
            meta["resource_type"] = type(type_or_obj).__name__
            if hasattr(type_or_obj, "pk"):
                meta["resource_id"] = str(type_or_obj.pk)
            elif hasattr(type_or_obj, "id"):
                meta["resource_id"] = str(type_or_obj.id)
        return self

    # ------------------------------------------------------------------
    # Timestamp & severity
    # ------------------------------------------------------------------

    def timestamp(self, ts: datetime | str) -> EventBuilder:
        """Set the event timestamp (datetime or ISO 8601 string)."""
        if isinstance(ts, datetime):
            self._data["timestamp"] = ts.isoformat()
        else:
            self._data["timestamp"] = ts
        return self

    def severity(self, severity: str) -> EventBuilder:
        """Set the event severity hint for the enricher."""
        self._data.setdefault("metadata", {})["_severity"] = severity
        return self

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send(self) -> None:
        """Send the event (non-blocking, via background thread)."""
        self._client.track_data(self._event, self._data)

    async def send_async(self) -> None:
        """Send the event asynchronously."""
        data = self._client._resolve_args()  # noqa: SLF001
        data.update(self._data)
        payload = self._client._build_payload(self._event, self._data)  # noqa: SLF001
        await self._client._send_async(payload)  # noqa: SLF001

    def to_dict(self) -> dict[str, Any]:
        """Return the built payload as a dict (for testing/inspection)."""
        return {"event": self._event, **self._data}
