"""Unit tests for the SOCWarden Python SDK."""

import os
import platform
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from socwarden import EventBuilder, SOCWarden
from socwarden.middleware import _request_context, get_request_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockUser:
    """Fake user model with .id and .email attributes."""

    def __init__(self, id: str, email: str) -> None:
        self.id = id
        self.email = email


class MockDjangoUser:
    """Fake Django user model with .pk and .email attributes."""

    def __init__(self, pk: int, email: str) -> None:
        self.pk = pk
        self.email = email


class MockResource:
    """Fake resource model with .pk attribute."""

    def __init__(self, pk: int) -> None:
        self.pk = pk


class MockResourceWithId:
    """Fake resource model with .id attribute."""

    def __init__(self, id: str) -> None:
        self.id = id


def make_mock_response(status_code: int = 202, headers: dict | None = None) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = '{"status": "accepted"}'
    resp.json.return_value = {"status": "accepted"}
    return resp


# ---------------------------------------------------------------------------
# 1. track() builds correct payload
# ---------------------------------------------------------------------------


class TestTrack:
    def test_track_builds_correct_payload(self) -> None:
        """track() should construct a payload with event, source, actor, ip, metadata, and context."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

            soc.track(
                "auth.login.success",
                actor="usr_1",
                actor_email="alice@example.com",
                ip="10.0.0.1",
                metadata={"mfa": True},
            )
            # track() dispatches to background thread; shut down to flush
            soc.close()

            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

            assert payload["event"] == "auth.login.success"
            assert payload["source"] == "sdk"
            assert payload["actor_id"] == "usr_1"
            assert payload["actor_email"] == "alice@example.com"
            assert payload["ip"] == "10.0.0.1"
            assert payload["metadata"] == {"mfa": True}

    def test_track_with_actor_object(self) -> None:
        """track() should read .id and .email from actor objects."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            user = MockUser(id="usr_42", email="bob@example.com")

            soc.track("auth.login.success", actor=user)
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["actor_id"] == "usr_42"
            assert payload["actor_email"] == "bob@example.com"

    def test_track_with_django_user(self) -> None:
        """track() should read .pk (Django convention) for actor_id."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            user = MockDjangoUser(pk=99, email="django@example.com")

            soc.track("auth.login.success", actor=user)
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["actor_id"] == "99"
            assert payload["actor_email"] == "django@example.com"

    def test_explicit_actor_id_overrides_actor_object(self) -> None:
        """Explicit actor_id kwarg should override the actor object's .id."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            user = MockUser(id="usr_old", email="old@example.com")

            soc.track("test.event", actor=user, actor_id="usr_override", actor_email="new@example.com")
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["actor_id"] == "usr_override"
            assert payload["actor_email"] == "new@example.com"


# ---------------------------------------------------------------------------
# 2. track_data() passes raw dict
# ---------------------------------------------------------------------------


class TestTrackData:
    def test_track_data_passes_raw_dict(self) -> None:
        """track_data() should send the raw dict fields in the payload."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

            soc.track_data("server.ssh.login.failure", {
                "actor_id": "root",
                "ip": "192.168.1.1",
                "metadata": {"port": 22},
            })
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["event"] == "server.ssh.login.failure"
            assert payload["source"] == "sdk"
            assert payload["actor_id"] == "root"
            assert payload["ip"] == "192.168.1.1"
            assert payload["metadata"] == {"port": 22}


# ---------------------------------------------------------------------------
# 3. EventBuilder fluent chain
# ---------------------------------------------------------------------------


class TestEventBuilder:
    def test_event_builder_chain(self) -> None:
        """EventBuilder fluent chain should build the correct dict."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        result = (
            soc.event("data.exported")
            .actor("usr_1")
            .actor_email("alice@example.com")
            .ip("10.0.0.1")
            .meta("format", "csv")
            .meta("rows", 1000)
            .resource("Report", "rpt_42")
            .to_dict()
        )
        soc.close()

        assert result["event"] == "data.exported"
        assert result["actor_id"] == "usr_1"
        assert result["actor_email"] == "alice@example.com"
        assert result["ip"] == "10.0.0.1"
        assert result["metadata"] == {
            "format": "csv",
            "rows": 1000,
            "resource_type": "Report",
            "resource_id": "rpt_42",
        }

    def test_event_builder_actor_object(self) -> None:
        """EventBuilder.actor() should read .id and .email from object."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        user = MockUser(id="usr_99", email="bob@example.com")

        result = soc.event("test.event").actor(user).to_dict()
        soc.close()

        assert result["actor_id"] == "usr_99"
        assert result["actor_email"] == "bob@example.com"

    def test_event_builder_actor_object_with_pk(self) -> None:
        """EventBuilder.actor() should prefer .pk over .id (Django convention)."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        user = MockDjangoUser(pk=77, email="django@example.com")

        result = soc.event("test.event").actor(user).to_dict()
        soc.close()

        assert result["actor_id"] == "77"
        assert result["actor_email"] == "django@example.com"

    def test_metadata_merges_multiple_calls(self) -> None:
        """Multiple metadata() calls should merge keys."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        result = (
            soc.event("test.event")
            .metadata({"a": 1, "b": 2})
            .metadata({"b": 3, "c": 4})
            .to_dict()
        )
        soc.close()

        assert result["metadata"] == {"a": 1, "b": 3, "c": 4}

    def test_timestamp_datetime(self) -> None:
        """timestamp() should convert datetime to ISO string."""
        from datetime import datetime, timezone

        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = soc.event("test.event").timestamp(dt).to_dict()
        soc.close()

        assert result["timestamp"] == "2025-01-15T12:00:00+00:00"

    def test_timestamp_string(self) -> None:
        """timestamp() should pass ISO string through."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        result = soc.event("test.event").timestamp("2025-01-15T12:00:00Z").to_dict()
        soc.close()

        assert result["timestamp"] == "2025-01-15T12:00:00Z"

    def test_severity_sets_metadata(self) -> None:
        """severity() should set _severity in metadata."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

        result = soc.event("test.event").severity("critical").to_dict()
        soc.close()

        assert result["metadata"]["_severity"] == "critical"

    def test_resource_object(self) -> None:
        """resource() should read class name and .pk from model instances."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        res = MockResource(pk=42)

        result = soc.event("test.event").resource(res).to_dict()
        soc.close()

        assert result["metadata"]["resource_type"] == "MockResource"
        assert result["metadata"]["resource_id"] == "42"

    def test_resource_object_with_id(self) -> None:
        """resource() should fall back to .id if no .pk."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        res = MockResourceWithId(id="res_abc")

        result = soc.event("test.event").resource(res).to_dict()
        soc.close()

        assert result["metadata"]["resource_type"] == "MockResourceWithId"
        assert result["metadata"]["resource_id"] == "res_abc"


# ---------------------------------------------------------------------------
# 4. _collect_context has SDK info
# ---------------------------------------------------------------------------


class TestCollectContext:
    def test_collect_context_has_sdk_info(self) -> None:
        """_collect_context() should include sdk.name, sdk.version, server.hostname, runtime, pid."""
        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        context = soc._collect_context()
        soc.close()

        assert context["sdk"]["name"] == "socwarden-python"
        assert context["sdk"]["version"] == "1.0.0"
        assert context["server"]["hostname"] == platform.node()
        assert context["server"]["runtime"] == f"Python {platform.python_version()}"
        assert context["server"]["pid"] == os.getpid()


# ---------------------------------------------------------------------------
# 5. 429 sets backoff
# ---------------------------------------------------------------------------


class TestBackoff:
    def test_429_sets_backoff(self) -> None:
        """A 429 response should set _backoff_until, causing subsequent calls to be skipped."""
        mock_resp = make_mock_response(429, headers={"Retry-After": "3600"})

        # Control the clock so the probe fires reliably regardless of CI uptime.
        # Layout: [first-send-check, first-send-set-backoff,
        #          second-send-check(400>probe_interval), second-send-set-backoff,
        #          third-send-check(within probe interval), fourth-send-check]
        fake_times = iter([0, 0, 400, 400, 401, 402])

        with patch("socwarden.client.time.monotonic", side_effect=fake_times), \
             patch.object(httpx.Client, "post", return_value=mock_resp) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")

            # Call _send directly (synchronous) to avoid thread pool timing issues
            payload = soc._build_payload("test.event", {})
            soc._send(payload)

            # backoff_until should now be set
            assert soc._backoff_until > 0

            # Second call: backoff is active but _last_probe is 0 so
            # (now - 0) >= probe_interval triggers a probe request
            soc._send(payload)

            # Third+ calls: within probe interval, should be silently dropped
            soc._send(payload)
            soc._send(payload)

            # Two actual HTTP calls: the first + one probe
            assert mock_post.call_count == 2

            soc.close()


# ---------------------------------------------------------------------------
# 6. sanitize_query_string
# ---------------------------------------------------------------------------


class TestSanitizeQueryString:
    def test_sanitize_query_string_redacts_sensitive(self) -> None:
        """Sensitive params (token, password, secret, key, etc.) should be redacted."""
        result = SOCWarden._sanitize_query_string("token=abc123&name=test&password=hunter2&safe=yes")
        assert "token=[REDACTED]" in result
        assert "name=test" in result
        assert "password=[REDACTED]" in result
        assert "safe=yes" in result
        assert "abc123" not in result
        assert "hunter2" not in result

    def test_sanitize_api_key_param(self) -> None:
        """Params containing 'key' should be redacted."""
        result = SOCWarden._sanitize_query_string("api_key=sk_live_123&page=1")
        assert "api_key=[REDACTED]" in result
        assert "page=1" in result

    def test_sanitize_auth_and_session(self) -> None:
        """Params containing 'auth' or 'session' should be redacted."""
        result = SOCWarden._sanitize_query_string("auth_token=xyz&session_id=abc&q=hello")
        assert "auth_token=[REDACTED]" in result
        assert "session_id=[REDACTED]" in result
        assert "q=hello" in result

    def test_sanitize_csrf_and_code(self) -> None:
        """Params containing 'csrf' or 'code' should be redacted."""
        result = SOCWarden._sanitize_query_string("csrf_token=abc&code=xyz&action=login")
        assert "csrf_token=[REDACTED]" in result
        assert "code=[REDACTED]" in result
        assert "action=login" in result

    def test_sanitize_empty_string(self) -> None:
        """Empty query string should return empty string."""
        assert SOCWarden._sanitize_query_string("") == ""

    def test_sanitize_no_value(self) -> None:
        """Params without values should not be redacted."""
        result = SOCWarden._sanitize_query_string("token&name=test")
        assert "token" in result
        assert "name=test" in result


# ---------------------------------------------------------------------------
# 6b. _sanitize_ip
# ---------------------------------------------------------------------------


class TestSanitizeIP:
    def test_invalid_ip_is_stripped(self) -> None:
        """Invalid IP strings should be excluded from the payload."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            soc.track("auth.login.success", ip="not-an-ip")
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert "ip" not in payload

    def test_valid_ipv4_is_kept(self) -> None:
        """Valid IPv4 addresses should be included in the payload."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            soc.track("auth.login.success", ip="10.0.0.1")
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["ip"] == "10.0.0.1"

    def test_valid_ipv6_is_kept(self) -> None:
        """Valid IPv6 addresses should be included in the payload."""
        with patch.object(httpx.Client, "post", return_value=make_mock_response()) as mock_post:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            soc.track("auth.login.success", ip="2001:db8::1")
            soc.close()

            payload = mock_post.call_args.kwargs["json"]
            assert payload["ip"] == "2001:db8::1"


# ---------------------------------------------------------------------------
# 7. Resolve actor from object
# ---------------------------------------------------------------------------


class TestResolveActorFromObject:
    def test_resolve_actor_from_object_with_id_and_email(self) -> None:
        """Object with .id and .email should resolve to actor_id and actor_email."""
        user = MockUser(id="usr_42", email="alice@example.com")
        data = SOCWarden._resolve_args(actor=user)

        assert data["actor_id"] == "usr_42"
        assert data["actor_email"] == "alice@example.com"

    def test_resolve_actor_from_object_with_pk(self) -> None:
        """Object with .pk should be preferred over .id (Django convention)."""
        user = MockDjangoUser(pk=99, email="django@example.com")
        data = SOCWarden._resolve_args(actor=user)

        assert data["actor_id"] == "99"
        assert data["actor_email"] == "django@example.com"

    def test_resolve_actor_string(self) -> None:
        """String actor should be used as actor_id directly."""
        data = SOCWarden._resolve_args(actor="usr_simple")
        assert data["actor_id"] == "usr_simple"
        assert "actor_email" not in data


# ---------------------------------------------------------------------------
# 8. Resource from object
# ---------------------------------------------------------------------------


class TestResourceFromObject:
    def test_resource_from_object_with_pk(self) -> None:
        """Object with .pk should resolve to metadata.resource_type (class name) and resource_id."""
        res = MockResource(pk=42)
        data = SOCWarden._resolve_args(resource=res)

        assert data["metadata"]["resource_type"] == "MockResource"
        assert data["metadata"]["resource_id"] == "42"

    def test_resource_from_object_with_id(self) -> None:
        """Object with .id (no .pk) should use .id for resource_id."""
        res = MockResourceWithId(id="res_abc")
        data = SOCWarden._resolve_args(resource=res)

        assert data["metadata"]["resource_type"] == "MockResourceWithId"
        assert data["metadata"]["resource_id"] == "res_abc"

    def test_resource_string_with_id(self) -> None:
        """String resource type with explicit resource_id."""
        data = SOCWarden._resolve_args(resource="Order", resource_id="ord_123")

        assert data["metadata"]["resource_type"] == "Order"
        assert data["metadata"]["resource_id"] == "ord_123"

    def test_resource_string_without_id(self) -> None:
        """String resource type without resource_id."""
        data = SOCWarden._resolve_args(resource="Report")

        assert data["metadata"]["resource_type"] == "Report"
        assert "resource_id" not in data["metadata"]


# ---------------------------------------------------------------------------
# Request context middleware integration
# ---------------------------------------------------------------------------


class TestRequestContext:
    def test_request_context_included_in_payload(self) -> None:
        """When middleware sets request context, it should appear in the payload."""
        # Simulate middleware setting context
        _request_context.method = "POST"
        _request_context.path = "/api/auth/login"
        _request_context.ip = "203.0.113.42"
        _request_context.user_agent = "Mozilla/5.0 TestBrowser"

        try:
            soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
            context = soc._collect_context()
            soc.close()

            assert context["request"]["method"] == "POST"
            assert context["request"]["path"] == "/api/auth/login"
            assert context["request"]["ip"] == "203.0.113.42"
            assert context["request"]["user_agent"] == "Mozilla/5.0 TestBrowser"
        finally:
            _request_context.clear()

    def test_request_context_cleared_after_clear(self) -> None:
        """After clear(), request context fields should be empty."""
        _request_context.method = "GET"
        _request_context.path = "/test"
        _request_context.clear()

        soc = SOCWarden(api_key="sk_test_123", endpoint="https://test.local")
        context = soc._collect_context()
        soc.close()

        assert "request" not in context
