"""Type definitions for the SOCWarden Python SDK."""

from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable


@runtime_checkable
class HasIdentity(Protocol):
    """Any object with an `id` attribute (e.g., Django User, SQLAlchemy model)."""

    id: Any


@runtime_checkable
class HasEmail(Protocol):
    """Any object with an `email` attribute."""

    email: str


@runtime_checkable
class HasPK(Protocol):
    """Any object with a `pk` attribute (Django model convention)."""

    pk: Any


class EventPayload(TypedDict, total=False):
    """Wire format sent to POST /v1/events."""

    event: str
    source: str
    actor_id: str
    actor_email: str
    ip: str
    user_agent: str
    metadata: dict[str, Any]
    timestamp: str
    context: dict[str, Any]


class SDKContext(TypedDict, total=False):
    """Context block attached to every event."""

    sdk: dict[str, str]
    server: dict[str, Any]
    request: dict[str, Any]
