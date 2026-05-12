# Security Audit Report

**Project**: SOCWarden Python SDK (`socwarden`)
**Date**: 2026-05-12
**Auditor**: Claude Security Audit
**Frameworks**: OWASP Top 10:2025 + NIST CSF 2.0
**Mode**: full --fix

---

## Executive Summary

| Metric | Count |
|--------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 2 |
| 🔵 Informational | 4 |
| 🔲 Gray-box findings | 0 |
| 📍 Security hotspots | 4 |
| 🧹 Code smells | 1 |
| **Total findings** | **13** |

**Overall Risk Assessment**: No critical or high-severity vulnerabilities were found. Two medium-severity issues were identified and fixed: (1) `Retry-After` header parsing that silently crashed on RFC 7231 date-format values, bypassing the rate-limit backoff and leaving the SDK free to hammer a rate-limited endpoint; (2) server response bodies logged verbatim, allowing a compromised ingestor to inject fake log lines into application logs. Two low-severity issues were also fixed: forged X-Forwarded-For IPs reaching the ingestor via the middleware context path (bypassing the `_sanitize_ip` guard applied to the top-level `ip` field), and ASGI middleware that set context before its `try/finally` block, risking partial leftover state. The dependency tree (httpx ≥0.28.0) has no known CVEs. TLS verification is enabled by default via httpx. API keys are never exposed in `__repr__`, logs, or exception messages.

---

## OWASP Top 10:2025 Coverage

| OWASP ID | Category | Findings | Status |
|----------|----------|----------|--------|
| A01:2025 | Broken Access Control | 0 | ✅ Acceptable |
| A02:2025 | Security Misconfiguration | 1 | 🔴 Needs Attention (FIXED — HTTPS-only enforced in production; warning in non-prod) |
| A03:2025 | Software Supply Chain Failures | 0 | ✅ Acceptable — no known CVEs in httpx |
| A04:2025 | Cryptographic Failures | 0 | ✅ Acceptable — TLS verification enabled by default |
| A05:2025 | Injection | 1 | 🔴 Needs Attention (FIXED — log injection from server response body) |
| A06:2025 | Insecure Design | 1 | 🔴 Needs Attention (FIXED — Retry-After bypass of backoff mechanism) |
| A07:2025 | Authentication Failures | 0 | ✅ Acceptable |
| A08:2025 | Software or Data Integrity Failures | 0 | ✅ Acceptable |
| A09:2025 | Security Logging and Alerting Failures | 1 | 🔴 Needs Attention (FIXED — log injection) |
| A10:2025 | Mishandling of Exceptional Conditions | 1 | 🔴 Needs Attention (FIXED — ValueError from date-format Retry-After) |

---

## NIST CSF 2.0 Coverage

| Function | Categories | Findings | Status |
|----------|-----------|----------|--------|
| GV (Govern) | GV.RM | 1 | 🔴 Needs Attention (FIXED — rate-limit bypass) |
| ID (Identify) | ID.AM, ID.RA | 0 | ✅ Acceptable |
| PR (Protect) | PR.AA, PR.DS, PR.PS | 2 | 🔴 Needs Attention (FIXED — XFF validation, HTTPS enforcement) |
| DE (Detect) | DE.CM, DE.AE | 1 | 🔴 Needs Attention (FIXED — log injection) |
| RS (Respond) | RS.MI | 1 | 🔴 Needs Attention (FIXED — backoff bypass) |
| RC (Recover) | RC.RP | 0 | ✅ Acceptable |

---

## Compliance Coverage

| Framework | Coverage | Details |
|-----------|----------|---------|
| CWE | 5 unique CWEs identified | CWE-117, CWE-20, CWE-400, CWE-390, CWE-319 |
| SANS/CWE Top 25 | 1/25 entries found | CWE-20 (Improper Input Validation) |
| OWASP ASVS 5.0 | 3/14 chapters with findings | V7 (Error Handling), V13 (API), V14 (Config) |
| PCI DSS 4.0.1 | 1 requirement relevant | 6.2.4 (input validation) |
| MITRE ATT&CK | 2 techniques mapped | T1499 (Endpoint DoS), T1565 (Data Manipulation) |
| SOC 2 | 2 criteria with findings | CC6.1 (Logical access), CC7.2 (Monitoring) |
| ISO 27001:2022 | 2 controls with findings | A.8.16 (Monitoring), A.8.28 (Secure coding) |

---

## 🟡 Medium Findings

### 🟡 [MEDIUM-001] Retry-After Date-Format String Causes ValueError — Backoff Not Applied

- **Severity**: 🟡 MEDIUM
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions), A06:2025 (Insecure Design)
- **CWE**: CWE-390 (Detection of Error Condition Without Action), CWE-400 (Uncontrolled Resource Consumption)
- **NIST CSF**: GV.RM (Risk Management), RS.MI (Incident Mitigation)
- **Compliance**: ASVS V7.4.1 | T1499 | CC7.2 | A.8.28
- **Location**: `socwarden/client.py:465` and `socwarden/client.py:523` (pre-fix)
- **Attack Vector**:
  1. An ingestor endpoint (compromised, misconfigured, or under load) responds with HTTP 429 and `Retry-After: Mon, 12 May 2025 10:00:00 GMT` (RFC 7231 date format, which is valid per the spec).
  2. `int("Mon, 12 May...")` raises `ValueError` inside `_send()`.
  3. The `ValueError` is not caught — it propagates to the `ThreadPoolExecutor` future, which swallows it silently.
  4. `_backoff_until` is never set, so the next event submission immediately retries.
  5. The SDK hammers the server at full rate despite a 429 response, worsening an outage or contributing to a DoS condition.
- **Impact**: Rate-limit backoff mechanism completely bypassed on servers that use date-format `Retry-After` headers. The SDK can generate a high volume of requests against a rate-limited endpoint, worsening service degradation.
- **Vulnerable Code** (pre-fix):
  ```python
  raw_retry = int(response.headers.get("Retry-After", self._backoff_duration))
  ```
- **Remediation**: Extracted to a dedicated `_parse_retry_after()` method with `try/except (ValueError, TypeError)` that falls back to `_backoff_duration`. Applied to both `_send()` and `_send_async()`.
  ```python
  def _parse_retry_after(self, header_value: str, default: int) -> int:
      try:
          raw = int(header_value)
      except (ValueError, TypeError):
          raw = default
      return min(max(raw, 0), self._max_backoff)
  ```

---

### 🟡 [MEDIUM-002] Server Response Body Logged via `%s` — Log Injection Possible

- **Severity**: 🟡 MEDIUM
- **OWASP**: A05:2025 (Injection), A09:2025 (Security Logging and Alerting Failures)
- **CWE**: CWE-117 (Improper Output Neutralization for Logs)
- **NIST CSF**: DE.CM (Continuous Monitoring), DE.AE (Anomaly Detection)
- **Compliance**: SANS Top 25 adjacent | ASVS V7.3.3 | T1565 | CC7.2 | A.8.16
- **Location**: `socwarden/client.py:476-480` and `socwarden/client.py:534-538` (pre-fix)
- **Attack Vector**:
  1. The ingestor is compromised or returns a crafted 4xx/5xx response body.
  2. The body contains newlines, e.g.: `"error\nCRITICAL: SQL injection detected from admin\nend"`.
  3. `response.text[:512]` preserves the newlines.
  4. `logger.warning("...status=%d): %s", status_code, truncated)` formats the body with `%s`, preserving newlines.
  5. The resulting log stream contains fabricated log lines that appear structurally identical to real application log entries.
  6. A SIEM or SOC analyst reads the injected lines and acts on false intelligence.
- **Impact**: Log spoofing/injection. A compromised or malicious ingestor endpoint can forge security-relevant log lines in the SDK consumer's application log. This could trigger false SIEM alerts, mislead incident responders, or mask real security events.
- **Vulnerable Code** (pre-fix):
  ```python
  truncated = response.text[:512]
  logger.warning(
      "SOCWarden: event send failed (status=%d): %s",
      response.status_code,
      truncated,
  )
  ```
- **Remediation**: Strip `\r` and `\n` from the truncated body before passing to the logger.
  ```python
  truncated = response.text[:512].replace("\r", " ").replace("\n", " ")
  logger.warning(
      "SOCWarden: event send failed (status=%d): %s",
      response.status_code,
      truncated,
  )
  ```

---

## 🟢 Low & 🔵 Informational Findings

### 🟢 [LOW-001] Middleware Stores Unvalidated X-Forwarded-For IP in Context

- **Severity**: 🟢 LOW
- **OWASP**: A05:2025 (Injection — data integrity), A06:2025 (Insecure Design)
- **CWE**: CWE-20 (Improper Input Validation)
- **NIST CSF**: PR.DS (Data Security)
- **Compliance**: SANS Top 25 #4 (CWE-20) | ASVS V5.1.3 | PCI DSS 6.2.4 | A.8.28
- **Location**: `socwarden/middleware.py` — `SOCWardenFlask._before_request()`, `SOCWardenDjangoMiddleware._get_client_ip()`, `SOCWardenASGIMiddleware.__call__()` (pre-fix)
- **Attack Vector**:
  1. Client sends `X-Forwarded-For: 999.999.999.999` or `X-Forwarded-For: ' OR 1=1--`.
  2. Middleware splits on `,` and stores the first value in `_request_context.ip`.
  3. `_collect_context()` writes `req_ctx.ip` directly to `context.request.ip` without calling `_sanitize_ip()`.
  4. The invalid/forged IP is sent to the ingestor as part of the event context.
  5. Inconsistency: the top-level `ip` field (passed via `track(ip=...)`) IS sanitized, but the middleware-derived context IP was not.
- **Impact**: Invalid or forged IP addresses can reach the ingestor, potentially confusing enrichment and geo-lookup logic. The ingestor should have its own validation but defence-in-depth requires the SDK to validate too.
- **Remediation**: Added `_validate_ip()` helper using `ipaddress.ip_address()` in `middleware.py`. All three middlewares now call `_validate_ip()` before storing the IP in context.

---

### 🟢 [LOW-002] ASGI Middleware Sets Context Before `try/finally` Block

- **Severity**: 🟢 LOW
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions)
- **CWE**: CWE-390 (Detection of Error Condition Without Action)
- **NIST CSF**: DE.AE (Anomaly Detection)
- **Location**: `socwarden/middleware.py:207-227` (pre-fix)
- **Attack Vector**:
  1. `SOCWardenASGIMiddleware.__call__()` assigns to `_request_context.*` at lines 207–220.
  2. This block sits BEFORE the `try: await self.app(...) finally: _request_context.clear()` at line 224.
  3. If any assignment in lines 207–220 raises an unexpected exception (e.g., a future Python/library change makes `scope.get()` raise), `_request_context.clear()` is never called.
  4. Partially-set context from the failed request persists in thread-local storage and bleeds into the next request served by the same thread.
- **Impact**: Context bleed between requests. A subsequent event tracked in the same thread would carry stale request metadata (IP, path, user-agent) from a previous request. In a multi-tenant or high-security context this could attach the wrong user's context to security events.
- **Remediation**: Moved all context-setting assignments inside the `try` block so `clear()` in `finally` is always executed.

---

### 🔵 [INFO-001] HTTPS-Only Enforcement Is Production-Gated

- **Severity**: 🔵 INFO
- **OWASP**: A02:2025 (Security Misconfiguration), A04:2025 (Cryptographic Failures)
- **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
- **NIST CSF**: PR.DS, PR.PS
- **Location**: `socwarden/client.py:56-65`
- **Finding**: The `https://` enforcement raises `ValueError` only when `SOCWARDEN_ENV=production` or `ENV=production` is set. In all other environments (staging, CI, dev), an HTTP endpoint only triggers a `logger.warning` and proceeds. This is a reasonable trade-off for developer convenience but means API keys are transmitted in cleartext in non-production deployments if misconfigured.
- **Recommendation**: This is intentional and acceptable for non-production use. Ensure the env variable is always set correctly in staging/CI pipelines and that CI secrets are not reused across environments.

---

### 🔵 [INFO-002] API Key Printed in `__init__.py` Docstring Example

- **Severity**: 🔵 INFO
- **OWASP**: A04:2025 (Cryptographic Failures)
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
- **NIST CSF**: PR.DS
- **Location**: `socwarden/__init__.py:7`, `socwarden/middleware.py:37,90,179`
- **Finding**: Docstring examples use placeholder `"sk_live_..."` and `"sk_..."` strings. These are illustrative and not real keys, so there is no actual vulnerability. However, if a developer copies the example literally, a real key would appear in source code.
- **Recommendation**: The placeholder format is clear. No change required. Ensure the README includes a note to load keys from environment variables rather than hardcoding.

---

### 🔵 [INFO-003] No `__del__` or `atexit` Registration for Thread Pool Cleanup

- **Severity**: 🔵 INFO
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions)
- **CWE**: CWE-404 (Improper Resource Shutdown)
- **NIST CSF**: DE.AE
- **Location**: `socwarden/client.py:79-93`
- **Finding**: The `ThreadPoolExecutor` is not registered with `atexit`. If the application exits without calling `soc.close()`, pending events in the queue may be dropped silently. Python's default `ThreadPoolExecutor` shutdown on interpreter exit does not guarantee all submitted tasks are flushed.
- **Recommendation**: Consider adding `atexit.register(self.close)` in `__init__` for a best-effort flush on normal interpreter exit. The context manager (`with SOCWarden(...) as soc:`) pattern already handles this correctly when used.

---

### 🔵 [INFO-004] No Dependency Vulnerabilities Found

- **Severity**: 🔵 INFO
- **OWASP**: A03:2025 (Software Supply Chain Failures)
- **CWE**: N/A
- **NIST CSF**: GV.SC
- **Location**: `pyproject.toml`
- **Finding**: `pip-audit` reports no known vulnerabilities in the dependency tree. The only runtime dependency is `httpx>=0.28.0`. Framework extras (flask, django, fastapi, starlette) are optional and not audited here as they are the user's responsibility.

---

## 📍 Security Hotspots

### [HOTSPOT-001] `_parse_retry_after` — Server-Controlled Backoff Duration

- **OWASP**: A06:2025
- **CWE**: CWE-400
- **NIST CSF**: GV.RM
- **Location**: `socwarden/client.py:444-461`
- **Why sensitive**: The backoff duration is entirely server-controlled. While clamped to `_max_backoff` (24 h), a compromised server can still silence the SDK for up to 24 hours per 429 response. The `_max_backoff` cap and the probe mechanism (`_probe_interval`) limit the damage but any change to these values requires careful threat-modelling.
- **Risk if modified**: Increasing `_max_backoff` or removing the probe mechanism enables a server-side DoS that permanently silences the SDK. Decreasing it excessively could cause the SDK to hammer a legitimate rate-limited server.
- **Review guidance**: Any PR that touches `_max_backoff`, `_probe_interval`, `_backoff_duration`, or the 429-handling branch needs a threat-model review.

---

### [HOTSPOT-002] `_sanitize_query_string` — Keyword-Based Redaction

- **OWASP**: A09:2025
- **CWE**: CWE-200
- **NIST CSF**: PR.DS
- **Location**: `socwarden/client.py:426-452`
- **Why sensitive**: The redaction list `("token", "key", "password", "secret", "code", "auth", "session", "csrf")` is keyword-based — it catches param names that *contain* any of these substrings. This is intentionally broad and catches most common cases, but new credential patterns (e.g. `otp`, `pin`, `bearer`) are not covered. The URL-decode bypass fix (using `unquote_plus`) is in place.
- **Risk if modified**: Narrowing the list could expose credentials in query strings. Removing the decode step would reintroduce the percent-encoding bypass.
- **Review guidance**: Any PR changing `sensitive` keywords or the decode logic must include a negative test (a new bypass attempt) and a positive test.

---

### [HOTSPOT-003] Async HTTP Client Lazy Initialization — Double-Checked Locking

- **OWASP**: A06:2025
- **CWE**: CWE-362 (Race Condition)
- **NIST CSF**: PR.DS
- **Location**: `socwarden/client.py:557-577`
- **Why sensitive**: Uses double-checked locking with a `threading.Lock` for one-time `AsyncClient` creation. This pattern is correct in CPython (GIL + memory model), but is inherently fragile in theory. The fast path (`_async_http is not None`) is intentionally lock-free.
- **Risk if modified**: Any change that makes the initialization multi-step (e.g., adding configuration after construction) without holding the lock for the whole sequence would introduce a race where two threads could create two `AsyncClient` instances.
- **Review guidance**: The initialization must remain atomic — construct the full `AsyncClient` inside the `with self._async_lock:` block and assign it in a single write.

---

### [HOTSPOT-004] Context Trust Boundary — `_collect_context()` Including Request Headers

- **OWASP**: A01:2025 (Broken Access Control)
- **CWE**: CWE-20 (Improper Input Validation)
- **NIST CSF**: PR.DS
- **Location**: `socwarden/client.py:365-397`
- **Why sensitive**: `_collect_context()` assembles a context dict from thread-local values set by middleware. Every field (`user_agent`, `referer`, `origin`, `accept_language`) is user-controlled via HTTP headers and is sent as-is to the ingestor. The ingestor is responsible for treating these as untrusted inputs for enrichment, but if future code adds server-side processing of these fields in the SDK itself (e.g., regex matching), they become injection vectors.
- **Risk if modified**: Adding any logic that processes or trusts `user_agent`, `referer`, or `origin` values could introduce injection vulnerabilities.
- **Review guidance**: These fields must always be treated as untrusted strings and never used in server-side logic within the SDK. The D1 FIX (removing the `X-SOCWarden-Context` header passthrough) was the correct mitigation; do not reintroduce any similar header-passthrough mechanism.

---

## 🧹 Code Smells

### [SMELL-001] `SDK_NAME` and `SDK_VERSION` Duplicated in `middleware.py`

- **OWASP**: A06:2025
- **CWE**: CWE-561 (Dead Code)
- **NIST CSF**: GV.RM
- **Location**: `socwarden/middleware.py:18-19` (duplicated from `socwarden/client.py:22-23`)
- **Pattern**: `SDK_NAME = "socwarden-python"` and `SDK_VERSION = "1.0.0"` are defined identically in both `client.py` and `middleware.py`. Neither constant is actually used in `middleware.py`.
- **Security implication**: During a version bump, one copy may be updated while the other is not, causing version skew in log messages or any future context metadata that references the middleware constants.
- **Suggestion**: Remove the duplicates from `middleware.py`. If the middleware ever needs these values, import them from `client.py`.

---

## Recommendations Summary

**Priority 1 — Already fixed in this audit:**
1. **Retry-After date-format crash** (`client.py`) — replaced `int()` with `_parse_retry_after()` that handles both RFC 7231 formats.
2. **Log injection from server response** (`client.py`) — strip `\r`/`\n` from truncated body before logging in both `_send()` and `_send_async()`.
3. **Unvalidated XFF IP in middleware context** (`middleware.py`) — added `_validate_ip()` helper used by all three middlewares.
4. **ASGI middleware context not in try/finally** (`middleware.py`) — moved all context-setting assignments inside the `try` block.

**Priority 2 — Recommended follow-up:**
5. **Atexit registration** (`client.py`) — add `atexit.register(self.close)` in `__init__` to flush pending events on normal interpreter exit.
6. **Remove dead constants from middleware.py** — import `SDK_NAME`/`SDK_VERSION` from `client.py` rather than duplicating.
7. **Extend redaction keyword list** — consider adding `otp`, `pin`, `bearer`, `api` to `_sanitize_query_string`'s `sensitive` tuple.

---

## Methodology

| Aspect | Details |
|--------|---------|
| Phases executed | 1–5 (full) |
| Frameworks detected | Python SDK; optional Flask 2+, Django 4+, FastAPI 0.100+/Starlette 0.27+ |
| White-box categories | All 20 OWASP attack categories examined |
| Gray-box testing | N/A — pure library SDK with no live server |
| Security hotspots | 4 identified (crypto/auth boundary, input/output, third-party, error handling) |
| Code smells | Structural (duplicated constants) |
| Packs loaded | none |
| Scope exclusions | .venv/, __pycache__/ excluded |
| Baseline comparison | No prior baseline |
| OWASP Top 10:2025 | 10/10 categories covered |
| NIST CSF 2.0 | GV, ID, PR, DE, RS, RC |
| CWE | 5 unique CWE IDs identified |
| SANS/CWE Top 25 | 1/25 matched (CWE-20) |
| ASVS 5.0 | V5, V7, V13, V14 chapters checked |
| Additional frameworks | PCI DSS 4.0.1, MITRE ATT&CK, SOC 2, ISO 27001:2022 |

---

*Report generated by Claude Security Audit*
