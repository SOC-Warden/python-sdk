"""Cross-service contract tests verifying the Python SDK payload matches the ingestor schema."""
import re
from unittest.mock import patch, MagicMock

import httpx

from socwarden import SOCWarden


# The ingestor's event type regex (from ingestor/internal/model/event.go).
EVENT_TYPE_REGEX = re.compile(r"^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$")

# Fields the ingestor's EventPayload struct accepts (POST /v1/events).
INGESTOR_ALLOWED_FIELDS = {
    "event",
    "source",
    "actor_id",
    "actor_email",
    "ip",
    "user_agent",
    "metadata",
    "timestamp",
    "context",
}


def _make_mock_response(status_code: int = 202) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = {}
    resp.text = '{"status": "accepted"}'
    resp.json.return_value = {"status": "accepted"}
    return resp


def test_payload_matches_ingestor_schema() -> None:
    """SDK track() payload must match the ingestor's expected EventPayload schema."""
    with patch.object(httpx.Client, "post", return_value=_make_mock_response()) as mock_post:
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        soc.track(
            "auth.login.success",
            actor_id="usr_123",
            actor_email="alice@example.com",
            ip="10.0.0.1",
            user_agent="TestAgent/1.0",
            metadata={"role": "admin"},
            timestamp="2026-03-18T10:30:00Z",
        )
        soc.close()

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")

        # Required fields
        assert "event" in payload
        assert payload["event"] == "auth.login.success"
        assert EVENT_TYPE_REGEX.match(payload["event"]), f"event does not match ingestor regex"

        assert "source" in payload
        assert payload["source"] == "sdk"

        # Optional fields with correct values
        assert payload["actor_id"] == "usr_123"
        assert payload["actor_email"] == "alice@example.com"
        assert payload["ip"] == "10.0.0.1"
        assert payload["user_agent"] == "TestAgent/1.0"
        assert isinstance(payload["metadata"], dict)
        assert payload["metadata"]["role"] == "admin"
        assert payload["timestamp"] == "2026-03-18T10:30:00Z"

        # Context must be an object with sdk/server blocks
        assert "context" in payload
        assert isinstance(payload["context"], dict)
        assert "sdk" in payload["context"]
        assert "server" in payload["context"]
        assert payload["context"]["sdk"]["name"] == "socwarden-python"
        assert payload["context"]["sdk"]["version"] == "1.0.0"

        # No unexpected fields
        for key in payload:
            assert key in INGESTOR_ALLOWED_FIELDS, (
                f"payload contains field '{key}' not in ingestor schema"
            )


def test_minimal_payload() -> None:
    """Minimal track() call should still produce valid ingestor payload."""
    with patch.object(httpx.Client, "post", return_value=_make_mock_response()) as mock_post:
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        soc.track("auth.logout")
        soc.close()

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")

        assert payload["event"] == "auth.logout"
        assert payload["source"] == "sdk"

        # No unexpected fields
        for key in payload:
            assert key in INGESTOR_ALLOWED_FIELDS


def test_event_type_format() -> None:
    """Common event types from the SDK must pass the ingestor's regex."""
    events = [
        "auth.login.success",
        "auth.login.failure",
        "auth.logout",
        "auth.mfa.enabled",
        "data.exported",
        "api.request.received",
        "page.view",
    ]
    for event in events:
        assert EVENT_TYPE_REGEX.match(event), f"event '{event}' does not match ingestor regex"


def test_source_is_sdk() -> None:
    """SDK must always set source to 'sdk'."""
    with patch.object(httpx.Client, "post", return_value=_make_mock_response()) as mock_post:
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        soc.track("auth.login.success")
        soc.close()

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert payload["source"] == "sdk"
