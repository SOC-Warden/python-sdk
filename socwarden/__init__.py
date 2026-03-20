"""SOCWarden Python SDK — security event tracking and threat detection.

Usage::

    from socwarden import SOCWarden, EventBuilder

    soc = SOCWarden(api_key="sk_live_...")

    # Simple tracking
    soc.track("auth.login.success", actor=user, ip="203.0.113.42")

    # Fluent builder
    soc.event("data.exported") \\
        .actor(user) \\
        .resource("Report", 42) \\
        .meta("format", "csv") \\
        .send()
"""

from .builder import EventBuilder
from .client import SOCWarden

__all__ = ["SOCWarden", "EventBuilder"]
__version__ = "1.0.0"
