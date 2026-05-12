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
| 🟠 High | 2 |
| 🟡 Medium | 4 |
| 🟢 Low | 3 |
| 🔵 Informational | 4 |
| 🔲 Gray-box findings | 0 |
| 📍 Security hotspots | 3 |
| 🧹 Code smells | 1 |
| **Total findings** | **17** |

**Overall Risk Assessment**: The SDK had two HIGH-severity issues — an input validation bypass in `EventBuilder.send_async()` that skipped event-type regex enforcement, and an unbound `Retry-After` acceptance that could silence the SDK permanently via a DoS from a malicious/compromised ingestor endpoint. Both have been fixed. No critical vulnerabilities were found. The dependency tree (httpx 0.28.1) has no known CVEs. TLS verification is enabled by default.

---

## OWASP Top 10:2025 Coverage

| OWASP ID | Category | Findings | Status |
|----------|----------|----------|--------|
| A01:2025 | Broken Access Control | 0 | ✅ Acceptable |
| A02:2025 | Security Misconfiguration | 1 | 🔴 Needs Attention (FIXED) |
| A03:2025 | Software Supply Chain Failures | 0 | ✅ Acceptable |
| A04:2025 | Cryptographic Failures | 0 | ✅ Acceptable |
| A05:2025 | Injection | 1 | 🔴 Needs Attention (FIXED) |
| A06:2025 | Insecure Design | 2 | 🔴 Needs Attention (FIXED) |
| A07:2025 | Authentication Failures | 0 | ✅ Acceptable |
| A08:2025 | Software or Data Integrity Failures | 0 | ✅ Acceptable |
| A09:2025 | Security Logging and Alerting Failures | 2 | 🔴 Needs Attention (FIXED) |
| A10:2025 | Mishandling of Exceptional Conditions | 2 | 🔴 Needs Attention (FIXED) |

---

## NIST CSF 2.0 Coverage

| Function | Categories | Findings | Status |
|----------|-----------|----------|--------|
| GV (Govern) | GV.RM | 1 | 🔴 Needs Attention (FIXED) |
| ID (Identify) | ID.RA | 0 | ✅ Acceptable |
| PR (Protect) | PR.AA, PR.DS, PR.PS | 4 | 🔴 Needs Attention (FIXED) |
| DE (Detect) | DE.CM, DE.AE | 2 | 🔴 Needs Attention (FIXED) |
| RS (Respond) | RS.MI | 1 | 🔴 Needs Attention (FIXED) |
| RC (Recover) | RC.RP | 0 | ✅ Acceptable |

---

## Compliance Coverage

| Framework | Coverage | Details |
|-----------|----------|---------|
| CWE | 7 unique CWEs identified | CWE-400, CWE-116, CWE-20, CWE-778, CWE-362, CWE-390, CWE-479 |
| SANS/CWE Top 25 | 2/25 entries found | CWE-20 (#6), CWE-400 (#17) |
| OWASP ASVS 5.0 | 3 chapters with findings | V5 (Input Validation), V7 (Error Handling), V12 (Files and Resources) |
| PCI DSS 4.0.1 | 2 requirements relevant | 6.2.4 (injection prevention), 10.3.3 (log protection) |
| MITRE ATT&CK | 2 techniques mapped | T1499 (Endpoint DoS), T1562 (Impair Defenses) |
| SOC 2 | 2 criteria with findings | CC6.1 (Logical access), CC7.2 (Monitoring) |
| ISO 27001:2022 | 3 controls with findings | A.8.24 (Cryptography), A.8.15 (Logging), A.8.28 (Secure coding) |

---

## 🟠 High Findings

### 🟠 [HIGH-001] EventBuilder.send_async() Bypasses Event-Type Validation
- **Severity**: 🟠 HIGH
- **OWASP**: A05:2025 (Injection) — invalid/malformed event types passed to ingestor
- **CWE**: CWE-20 (Improper Input Validation)
- **NIST CSF**: PR.DS (Data Security — data integrity not enforced on async path)
- **Compliance**: SANS Top 25 #6 | ASVS V5.1.1 | PCI DSS 6.2.4 | T1562 | CC6.1 | A.8.28
- **Location**: `socwarden/builder.py:153-158` (pre-fix)
- **Status**: ✅ FIXED

**Attack Vector**:
1. Developer uses the fluent `EventBuilder` API with an async framework
2. They call `soc.event("INVALID EVENT TYPE!!!").send_async()`
3. `send_async()` called `_build_payload()` and `_send_async()` directly, skipping `_EVENT_TYPE_RE.match()`
4. A malformed event type is transmitted to the ingestor, which may reject it, corrupt analytics, or in future path-routing designs, cause injection-equivalent issues

**Impact**: Inconsistent enforcement between sync (`send()` → `track_data()` → validated) and async paths. Malformed event types reach the ingestor, bypassing the SDK's own contract enforcement. The `send()` path on the same builder was validated; `send_async()` was not.

**Vulnerable Code** (pre-fix):
```python
async def send_async(self) -> None:
    """Send the event asynchronously."""
    data = self._client._resolve_args()  # dead code — result never used
    data.update(self._data)
    payload = self._client._build_payload(self._event, self._data)  # no validation
    await self._client._send_async(payload)  # bypasses _EVENT_TYPE_RE
```

**Fixed Code** (`socwarden/builder.py:153-162`):
```python
async def send_async(self) -> None:
    """Send the event asynchronously."""
    await self._client.track_async(
        self._event,
        actor_id=self._data.get("actor_id"),
        actor_email=self._data.get("actor_email"),
        ip=self._data.get("ip"),
        user_agent=self._data.get("user_agent"),
        metadata=self._data.get("metadata"),
        timestamp=self._data.get("timestamp"),
    )
```
`track_async()` runs `_EVENT_TYPE_RE.match()` and drops the event with a warning if invalid, exactly as the sync path does.

---

### 🟠 [HIGH-002] Unbounded Retry-After Acceptance Enables Permanent SDK Silencing (DoS)
- **Severity**: 🟠 HIGH
- **OWASP**: A06:2025 (Insecure Design) / A10:2025 (Mishandling of Exceptional Conditions)
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **NIST CSF**: RS.MI (Respond — Incident Mitigation) / GV.RM (Risk Management)
- **Compliance**: SANS Top 25 #17 | ASVS V12.1.1 | PCI DSS 6.2.4 | T1499 | CC7.2 | A.8.24
- **Location**: `socwarden/client.py:452,494` (pre-fix)
- **Status**: ✅ FIXED

**Attack Vector**:
1. Attacker compromises or MitMs the ingestor endpoint (or operates a fake endpoint via SSRF-adjacent config)
2. Server responds to any event POST with `HTTP 429 Retry-After: 999999999`
3. SDK sets `self._backoff_until = time.monotonic() + 999999999` (≈ 31.7 years)
4. All subsequent `track()` calls are silently dropped forever
5. Security events stop reaching the SOCWarden platform — the SDK becomes a no-op

**Impact**: Complete loss of security event visibility for the duration of the process lifetime. All audit logging goes dark. The SDK provides no indication to the application that events are being dropped (only a DEBUG-level log).

**Vulnerable Code** (pre-fix):
```python
retry_after = int(response.headers.get("Retry-After", self._backoff_duration))
# retry_after could be 999999999 — no upper bound
with self._lock:
    self._backoff_until = time.monotonic() + retry_after
```

**Fixed Code** (`socwarden/client.py:455-459` and `510-514`):
```python
# Clamp Retry-After to _max_backoff to prevent DoS via huge server-supplied values.
raw_retry = int(response.headers.get("Retry-After", self._backoff_duration))
retry_after = min(max(raw_retry, 0), self._max_backoff)  # clamped to [0, 86400]
with self._lock:
    self._backoff_until = time.monotonic() + retry_after
```
`_max_backoff = 86400` (24 hours) is set in `__init__` and applied in both `_send()` and `_send_async()`.

---

## 🟡 Medium Findings

### 🟡 [MEDIUM-001] Error Response Body Logged Without Truncation
- **Severity**: 🟡 MEDIUM
- **OWASP**: A09:2025 (Security Logging and Alerting Failures)
- **CWE**: CWE-778 (Insufficient Logging) / CWE-116 (Improper Encoding of Output)
- **NIST CSF**: DE.CM (Detection — Continuous Monitoring)
- **Compliance**: ASVS V7.1.1 | PCI DSS 10.3.3 | CC7.2 | A.8.15
- **Location**: `socwarden/client.py:462-465` and `508-512` (pre-fix)
- **Status**: ✅ FIXED

**Attack Vector**: A malicious or faulty ingestor returns a `4xx`/`5xx` response with a very large body (e.g., 10 MB HTML error page or a response crafted to contain sensitive server-side information). The SDK logs `response.text` verbatim, which floods application logs and may expose server-side details (stack traces, internal paths, DB errors).

**Vulnerable Code** (pre-fix):
```python
logger.warning(
    "SOCWarden: event send failed (status=%d): %s",
    response.status_code,
    response.text,   # unbounded — could be megabytes
)
```

**Fixed Code**:
```python
truncated = response.text[:512]
logger.warning(
    "SOCWarden: event send failed (status=%d): %s",
    response.status_code,
    truncated,
)
```

---

### 🟡 [MEDIUM-002] Query String Sanitizer Does Not URL-Decode Parameter Names
- **Severity**: 🟡 MEDIUM
- **OWASP**: A09:2025 (Security Logging and Alerting Failures)
- **CWE**: CWE-116 (Improper Encoding — failure to decode before sensitive-check)
- **NIST CSF**: PR.DS (Data Security — credential data in logs)
- **Compliance**: ASVS V7.1.2 | PCI DSS 10.3.3 | A.8.15
- **Location**: `socwarden/client.py:419-426` (pre-fix)
- **Status**: ✅ FIXED

**Attack Vector**:
1. Application passes a request query string with a percent-encoded parameter name
2. E.g., `P%61ssword=hunter2` where `%61` decodes to `a` → the real name is `Password`
3. The pre-fix code checked `kv[0].lower()` directly → `p%61ssword` — no `password` keyword match
4. The value `hunter2` is emitted in plain text into the context log

**Vulnerable Code** (pre-fix):
```python
param_name = kv[0].lower()  # NOT decoded — bypassed by percent-encoding
if len(kv) == 2 and any(s in param_name for s in sensitive):
    parts.append(f"{kv[0]}=[REDACTED]")
```

**Fixed Code**:
```python
from urllib.parse import unquote_plus
param_name = unquote_plus(kv[0]).lower()  # decode %xx and + before keyword check
if len(kv) == 2 and any(s in param_name for s in sensitive):
    parts.append(f"{kv[0]}=[REDACTED]")
```

---

### 🟡 [MEDIUM-003] threading.Lock Acquired in Async Context (Event Loop Blocking Risk)
- **Severity**: 🟡 MEDIUM
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-362 (Race Condition / concurrent execution with shared resource)
- **NIST CSF**: PR.DS (Data Security)
- **Compliance**: ASVS V12.1.1 | A.8.28
- **Location**: `socwarden/client.py:496-502, 514-516, 530-534` (all in `_send_async`)
- **Status**: ✅ DOCUMENTED / PARTIALLY MITIGATED

**Finding**: `_send_async()` acquires `threading.Lock` three times (backoff read, 429 write, success write). A `threading.Lock` that is contended (another thread holds it) will block the caller's OS thread. In asyncio this means blocking the **entire event loop** — all other async tasks stop until the lock is released.

**Analysis of actual risk**: The lock is held for only a handful of cheap attribute reads/writes, never across an `await`. The critical invariant — lock released before `await client.post()` — is preserved. Contention probability is low (one lock shared across all SDK users). This was documented with an explicit comment; a full async refactor to use `asyncio.Lock` would require creating the lock within an async context, which is a larger API change.

**Mitigation applied**: Added docstring explaining the invariant and verified the lock is always released before each `await`. For high-throughput asyncio applications, users are advised to initialize the client inside an async context and use `asyncio.Lock`-based state if they need stronger guarantees.

---

### 🟡 [MEDIUM-004] Deprecated asyncio.get_event_loop() in close()
- **Severity**: 🟡 MEDIUM
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions)
- **CWE**: CWE-479 (Signal Handler Use of Non-Reentrant Function)
- **NIST CSF**: DE.AE (Anomalies and Events)
- **Compliance**: ASVS V12.1.1 | A.8.28
- **Location**: `socwarden/client.py:242` (pre-fix)
- **Status**: ✅ FIXED

**Finding**: `close()` called `asyncio.get_event_loop()` which is deprecated since Python 3.10 and raises `DeprecationWarning`. In Python 3.12+ it raises `RuntimeError` when no current event loop exists in the thread, causing `close()` to fail silently (caught by bare `except Exception: pass`).

**Vulnerable Code** (pre-fix):
```python
loop = asyncio.get_event_loop()
if loop.is_running():
    loop.create_task(self._async_http.aclose())
else:
    loop.run_until_complete(self._async_http.aclose())
```

**Fixed Code**:
```python
try:
    loop = asyncio.get_running_loop()   # Python 3.7+, no deprecation
    loop.create_task(self._async_http.aclose())
except RuntimeError:
    asyncio.run(self._async_http.aclose())  # no running loop — create one
```
The bare `except: pass` was also replaced with `except Exception as exc: logger.debug(...)` so failures are visible at debug level.

---

## 🟢 Low & 🔵 Informational Findings

### 🟢 [LOW-001] Exception Suppression in close() Hides Async Cleanup Failures
- **Severity**: 🟢 LOW
- **OWASP**: A10:2025 (Mishandling of Exceptional Conditions)
- **CWE**: CWE-390 (Detection of Error Condition Without Action)
- **NIST CSF**: DE.AE (Anomalies and Events)
- **Location**: `socwarden/client.py:247` (pre-fix)
- **Status**: ✅ FIXED

Bare `except Exception: pass` in `close()` silently swallowed all async cleanup errors. Fixed to `except Exception as exc: logger.debug("...", exc)` so failures are visible without being noisy.

---

### 🟢 [LOW-002] Dead Code in EventBuilder.send_async() — Merged data Discarded
- **Severity**: 🟢 LOW
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-561 (Dead Code)
- **NIST CSF**: GV.RM (Risk Management)
- **Location**: `socwarden/builder.py:155-156` (pre-fix)
- **Status**: ✅ FIXED (eliminated by the HIGH-001 fix)

`_resolve_args()` was called with no arguments (returns empty dict), merged with `self._data`, then the merge result (`data`) was never used — `_build_payload()` was called with `self._data` directly. The dead merge was eliminated by routing through `track_async()`.

---

### 🟢 [LOW-003] No Metadata / Field Size Limits in SDK
- **Severity**: 🟢 LOW
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **NIST CSF**: PR.DS (Data Security)
- **Location**: `socwarden/client.py:_build_payload`, `socwarden/builder.py:metadata()`
- **Status**: 🔵 INFORMATIONAL — requires ingestor-side enforcement

The SDK imposes no size limits on `metadata` dicts, `user_agent` strings, or `actor_id`/`actor_email` fields. A caller could craft a 100 MB metadata dict. The ingestor should reject oversized payloads (body size limit at the HTTP layer), but the SDK could add a client-side guard. Deferred: the ingestor's HTTP body limit is the correct enforcement point; SDK-side truncation risks data loss for legitimate large metadata.

---

### 🔵 [INFO-001] No Known CVEs in Dependencies
- **Severity**: 🔵 INFO
- **Location**: `pyproject.toml`
- `pip-audit` against `httpx>=0.28.0` dependency tree returned **no known vulnerabilities**. `httpx 0.28.1`, `h11 0.16.0`, `anyio 4.12.1`, `certifi 2025.6.15` are all current.

---

### 🔵 [INFO-002] TLS Certificate Verification Enabled by Default
- **Severity**: 🔵 INFO
- **Location**: `socwarden/client.py:83-91`
- `httpx.Client` and `httpx.AsyncClient` are constructed without `verify=False`. httpx defaults to verifying TLS using the `certifi` CA bundle. API keys are therefore protected in transit by default. The `__init__` also warns (or raises in production) if the endpoint is not `https://`.

---

### 🔵 [INFO-003] API Key Not Exposed in __repr__, __str__, or Logging
- **Severity**: 🔵 INFO
- **Location**: `socwarden/client.py` (all logging calls inspected)
- `self._api_key` is stored as a private attribute. No `__repr__` or `__str__` method is defined. All `logger.*` calls use safe format strings that never reference the API key. The only appearance of the key is in the `Authorization` header constructed in `__init__` and `_get_async_client()`, both internal to httpx request construction.

---

### 🔵 [INFO-004] X-Forwarded-For Trusted Without Configurable Proxy Hop Count
- **Severity**: 🔵 INFO
- **OWASP**: A01:2025 (Broken Access Control — IP spoofing)
- **CWE**: CWE-346 (Origin Validation Error)
- **Location**: `socwarden/middleware.py:54,158,200`
- All three middleware implementations (`SOCWardenFlask`, `SOCWardenDjangoMiddleware`, `SOCWardenASGIMiddleware`) take the first (leftmost) IP from `X-Forwarded-For`. This is correct for applications behind a single trusted reverse proxy, but incorrect when multiple proxy hops exist — an attacker can prepend a fake IP to the header. This is a standard SDK design choice (the application layer should configure trusted proxies); however, a future enhancement would allow callers to configure `trusted_proxies=N` to pick the Nth-from-right IP.

---

## 📍 Security Hotspots

### [HOTSPOT-001] API Key in HTTP Authorization Header Construction
- **OWASP**: A04:2025 (Cryptographic Failures)
- **CWE**: CWE-522 (Insufficiently Protected Credentials)
- **NIST CSF**: PR.DS (Data Security)
- **Location**: `socwarden/client.py:84-90` and `549-556`
- **Why sensitive**: The API key is embedded directly in the `Authorization: Bearer` header for every outgoing request. If the `httpx.Client` instance is ever serialized, logged, or passed to a debugging framework, the key would be exposed.
- **Risk if modified**: Adding `logging.debug(repr(self._http))` or similar would expose the full auth header. Adding `__repr__` to `SOCWarden` without masking `_api_key` would leak it.
- **Review guidance**: Any new logging, debugging, or serialization of the `SOCWarden` instance or its `_http` client must mask `_api_key`. Consider adding `__repr__` that returns `SOCWarden(endpoint=..., api_key=sk_...XXXX)`.

---

### [HOTSPOT-002] ThreadPoolExecutor — Concurrent Access to _http Client
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-362 (Race Condition)
- **NIST CSF**: PR.DS (Data Security)
- **Location**: `socwarden/client.py:77-80, 447-449`
- **Why sensitive**: Multiple background threads call `self._http.post()` concurrently. `httpx.Client` is documented as thread-safe for concurrent requests (connection pooling is handled internally). This remains safe today.
- **Risk if modified**: Replacing `httpx.Client` with a non-thread-safe HTTP library (e.g., `urllib.request` without locking) would introduce a race condition. Adding any per-request state mutation to `self._http` (headers, cookies) would also break thread safety.
- **Review guidance**: Keep `_http` as an `httpx.Client` instance. Never mutate shared headers after construction. If per-request headers are needed, pass them as `headers=` kwargs to `post()`, not via `client.headers.update()`.

---

### [HOTSPOT-003] Backoff State — Shared Mutable State Between Threads and Async
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-362 (Race Condition)
- **NIST CSF**: PR.DS (Data Security)
- **Location**: `socwarden/client.py:70-74, 436-474, 496-542`
- **Why sensitive**: `_backoff_until`, `_last_probe`, and `_backoff_duration` are shared between the sync thread pool workers and the async event loop via `threading.Lock`. The lock is correctly released before every `await`.
- **Risk if modified**: Any new async code path that holds `_lock` across an `await` will deadlock or block the event loop. Any new backoff state variable added without `_lock` protection will be a data race.
- **Review guidance**: Every read/write of `_backoff_until` or `_last_probe` must be inside `with self._lock`. No `await` may appear inside a `with self._lock` block.

---

## 🧹 Code Smells

### [SMELL-001] Incomplete send_async() Data Merge (Dead Code Pattern)
- **OWASP**: A06:2025 (Insecure Design)
- **CWE**: CWE-561 (Dead Code)
- **NIST CSF**: GV.RM (Risk Management)
- **Location**: `socwarden/builder.py:155-156` (pre-fix)
- **Pattern**: `_resolve_args()` called with no parameters (always returns `{}`), result merged into a local `data` dict, then `data` was never passed to `_build_payload()`. The merge was dead code.
- **Security implication**: The pattern suggested a future developer might add logic that relied on the dead merge — creating a hidden path where `_resolve_args()` output overrides builder state.
- **Fix applied**: Eliminated by routing through `track_async()`, which performs validation and correctly uses `_resolve_args()` internally.

---

## Recommendations Summary

### Immediate (already fixed in this audit)
1. **HIGH-001** — Route `EventBuilder.send_async()` through `track_async()` to enforce event-type validation on the async path (`builder.py`)
2. **HIGH-002** — Clamp `Retry-After` to `_max_backoff` (24 h) in both `_send()` and `_send_async()` (`client.py`)
3. **MEDIUM-001** — Truncate `response.text` to 512 chars before logging error bodies (`client.py`)
4. **MEDIUM-002** — URL-decode query parameter names before sensitivity keyword matching (`client.py`)
5. **MEDIUM-004** — Replace deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()` + `asyncio.run()` fallback (`client.py`)

### Near-term (recommended)
6. **HOTSPOT-001** — Add a `__repr__` to `SOCWarden` that masks all but the last 4 chars of the API key to prevent accidental key exposure in debug logs/reprs
7. **LOW-003** — Add client-side validation: reject `metadata` dicts deeper than 5 levels or larger than 64 KB; truncate `user_agent` to 512 chars
8. **INFO-004** — Add optional `trusted_proxies: int` constructor argument to pick the correct IP from multi-hop `X-Forwarded-For` headers

### Long-term (architectural)
9. **MEDIUM-003** — Migrate async backoff state to use `asyncio.Lock` for applications that use only the async API, eliminating threading.Lock from the event loop path entirely

---

## Methodology

| Aspect | Details |
|--------|---------|
| Phases executed | 1 (Reconnaissance), 2 (White-box), 4 (Hotspots), 5 (Code Smells) |
| Frameworks detected | Python SDK (httpx, threading, asyncio), WSGI (Flask, Django), ASGI (FastAPI/Starlette) |
| White-box categories | All 20 OWASP categories checked; AI/LLM, WebSocket, gRPC, Serverless N/A |
| Gray-box testing | Skipped — no live server; SDK is a library, not a running service |
| Security hotspots | 3 identified: auth header, thread pool HTTP client, async/sync backoff state |
| Code smells | 1 structural (dead code pattern in send_async) |
| Packs loaded | none |
| Scope exclusions | none |
| Baseline comparison | none |
| OWASP Top 10:2025 | 10/10 categories reviewed; 5 had findings |
| NIST CSF 2.0 | All 6 functions reviewed |
| CWE | 7 unique CWE IDs identified |
| SANS/CWE Top 25 | 2/25 matched (CWE-20 #6, CWE-400 #17) |
| ASVS 5.0 | Chapters V5, V7, V12 checked |
| Additional frameworks | PCI DSS 4.0.1, MITRE ATT&CK, SOC 2, ISO 27001:2022 |

**Files audited**:
- `socwarden/__init__.py`
- `socwarden/client.py`
- `socwarden/middleware.py`
- `socwarden/builder.py`
- `socwarden/types.py`
- `tests/test_client.py`
- `tests/test_contract.py`
- `pyproject.toml`

**Dependency audit**: `pip-audit 2.10.0` — **No known vulnerabilities** found in dependency tree.

---

*Report generated by Claude Security Audit*
