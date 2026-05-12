# SOCWarden Python SDK

Python SDK for [SOCWarden](https://socwarden.com) — security event tracking and threat detection.

## Installation

```bash
pip install socwarden
```

With framework middleware support:

```bash
pip install socwarden[flask]
pip install socwarden[django]
pip install socwarden[fastapi]
```

## Quick Start

```python
from socwarden import SOCWarden

soc = SOCWarden(api_key="sk_live_...")

# Track a security event
soc.track("auth.login.success", actor_id="usr_123", actor_email="john@example.com")
```

## Usage

### Track with Named Arguments

```python
soc.track(
    "auth.login.success",
    actor=user,              # object with .id/.pk and .email
    ip="203.0.113.42",
    user_agent="Mozilla/5.0 ...",
    metadata={"mfa": True, "method": "totp"},
)
```

The `actor` parameter accepts:
- A string (treated as actor ID)
- Any object with `.id` or `.pk` and `.email` attributes (Django User, SQLAlchemy model, etc.)

### Track with Raw Dict

```python
soc.track_data("auth.login.failure", {
    "actor_email": "john@example.com",
    "ip": "203.0.113.42",
    "metadata": {"reason": "invalid_password", "attempts": 3},
})
```

### Fluent Event Builder

```python
soc.event("data.exported") \
    .actor(user) \
    .resource("Report", report_id) \
    .meta("format", "csv") \
    .meta("rows", 1500) \
    .ip(request.remote_addr) \
    .send()
```

Builder methods:

| Method | Description |
|--------|-------------|
| `.actor(obj_or_id, email=None)` | Set actor from object or string ID |
| `.actor_id(id)` | Set actor ID directly |
| `.actor_email(email)` | Set actor email directly |
| `.ip(ip)` | Set source IP address |
| `.user_agent(ua)` | Set User-Agent string |
| `.metadata(dict)` | Merge metadata dict |
| `.meta(key, value)` | Set single metadata key |
| `.resource(type_or_obj, id=None)` | Attach resource |
| `.timestamp(dt_or_str)` | Set event timestamp |
| `.severity(level)` | Set severity hint |
| `.send()` | Send the event (non-blocking) |
| `.send_async()` | Send the event (async) |

### Async Usage

For asyncio applications (FastAPI, aiohttp, etc.):

```python
await soc.track_async(
    "auth.login.success",
    actor=user,
    ip=request.client.host,
)
```

### Resource Tracking

Track which resource was acted upon:

```python
# With a string type and ID
soc.event("resource.deleted") \
    .actor(user) \
    .resource("Order", order_id) \
    .send()

# With a model object (reads class name + .pk/.id)
soc.event("resource.updated") \
    .actor(user) \
    .resource(order) \
    .send()
```

## Framework Middleware

### Flask

```python
from flask import Flask
from socwarden import SOCWarden
from socwarden.middleware import SOCWardenFlask

app = Flask(__name__)
soc = SOCWarden(api_key="sk_live_...")
SOCWardenFlask(app, soc)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form)
    soc.track("auth.login.success", actor=user)
    # IP and User-Agent are automatically captured by middleware
    return redirect("/dashboard")
```

### Django

Add the middleware to `settings.py`:

```python
# settings.py
from socwarden import SOCWarden

SOCWARDEN_CLIENT = SOCWarden(api_key="sk_live_...")

MIDDLEWARE = [
    "socwarden.middleware.SOCWardenDjangoMiddleware",
    # ... other middleware
]
```

Or configure via settings keys:

```python
# settings.py
SOCWARDEN_API_KEY = "sk_live_..."
SOCWARDEN_ENDPOINT = "https://ingest.socwarden.com"

MIDDLEWARE = [
    "socwarden.middleware.SOCWardenDjangoMiddleware",
    # ...
]
```

Then in your views:

```python
from django.conf import settings

def login_view(request):
    user = authenticate(request, username=username, password=password)
    settings.SOCWARDEN_CLIENT.track("auth.login.success", actor=user)
    return redirect("/dashboard")
```

### FastAPI / Starlette

```python
from fastapi import FastAPI, Request
from socwarden import SOCWarden
from socwarden.middleware import SOCWardenASGIMiddleware

app = FastAPI()
soc = SOCWarden(api_key="sk_live_...")
app.add_middleware(SOCWardenASGIMiddleware, client=soc)

@app.post("/login")
async def login(request: Request):
    user = await authenticate(request)
    await soc.track_async("auth.login.success", actor=user)
    return {"status": "ok"}
```

## Event Type Format

Event types must match the pattern: `^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$`

Examples:
- `auth.login.success`
- `auth.login.failure`
- `data.exported`
- `server.ssh.login.failure`
- `resource.updated`

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `api_key` | (required) | Bearer token for the ingestor API |
| `endpoint` | `https://ingest.socwarden.com` | Ingestor base URL |
| `timeout` | `5.0` | HTTP request timeout in seconds |
| `max_workers` | `4` | Background thread pool size |
| `auto_context` | `True` | Attach SDK/server context to events |

## Context Manager

The client can be used as a context manager to ensure clean shutdown:

```python
with SOCWarden(api_key="sk_live_...") as soc:
    soc.track("auth.login.success", actor_id="usr_123")
# Background threads and HTTP client are shut down here
```

## License

MIT
