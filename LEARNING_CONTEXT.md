# AMaze Ingest — Python Learning Context

## What this file is for

This file gives you everything you need to create a graded series of Python practice
problems and mini-projects for a specific learner. Read the full context before
generating any exercises.

---

## About the learner

- Name: Vivek
- Background: understands general programming concepts but is new to Python
- Goal: reach the point where he can read, understand, and contribute to a real
  production Python codebase (amaze-ingest, described below)
- Has watched introductory videos on Python basics and how HTTP/APIs work
- Has NOT yet written real Python code — this practice track is his first hands-on work
- Responds well to context: knowing WHY something exists in real code makes it click

---

## About the codebase he'll be working in

**amaze-ingest** is a Python/FastAPI microservice that is part of AMaze — an enterprise
cybersecurity deception platform. Its job is to:

1. Listen to a message bus (NATS) for incoming attack events from honeypot servers
2. Parse each raw event (e.g. "Failed password for admin from 91.108.56.142")
3. Enrich it with geolocation data (country, lat/lon) and threat reputation scores
4. Store the enriched event in PostgreSQL
5. Broadcast it live to a dashboard via WebSocket + Redis pub/sub
6. Auto-create alert tickets for high-threat events

The service is entirely async Python using FastAPI. Everything in it maps to one of
the patterns below.

---

## Patterns to teach — in learning order

Work through these in order. Each section has: the concept, a real snippet from the
codebase, and guidance on what the exercise should cover.

---

### Level 1 — Foundation (do these first)

#### 1.1 Variables, data types, dictionaries

Dictionaries are the core data structure throughout this codebase. Every attack event
is a `dict`. The learner needs to be completely comfortable with them.

Real usage — every parsed event is a dict:
```python
event = {
    "protocol": "SSH",
    "src_ip": "91.108.56.142",
    "username": "admin",
    "threat_score": 95,
    "country": "Netherlands",
}
```

Real usage — `.get()` with a default (used hundreds of times):
```python
src_ip = event.get("src_ip") or ""
protocol = event.get("protocol") or "UNKNOWN"
```

Real usage — dict unpacking to merge two dicts without mutating the original:
```python
# This is used constantly throughout the pipeline
event = {**event, **geo_data}
# Equivalent to: create new dict with all keys from event, then overwrite/add keys from geo_data
```

**Exercise goals:** create dicts, access keys, use `.get()`, merge dicts with `**`.

---

#### 1.2 Functions — arguments, return values, None

Real usage — a parser function that either returns a dict or returns None:
```python
def parse_ssh_log(logline: str, metadata: dict) -> dict | None:
    if metadata.get("username"):
        return {**metadata, "protocol": "SSH", "logline": logline}
    return None
```

Real usage — helper functions that return a typed value or None:
```python
def _safe_int(val: object) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
```

**Exercise goals:** write functions that accept arguments, return values, handle the
case where there's nothing useful to return (return None), call other functions.

---

#### 1.3 Type hints

Type hints appear on almost every function signature. They don't change what the
code does — they're documentation for the reader (and for tools like mypy/pylance
that check for mistakes).

Real patterns used in this codebase:
```python
def parse_ssh_log(logline: str, metadata: dict) -> dict | None:  # str, dict, optional return
def _safe_int(val: object) -> int | None:                         # | None = "could be None"
def _is_private_ip(ip_str: str) -> bool:                         # bool return
_TOPIC_PARSERS: dict[str, ...] = { ... }                         # typed variable
self._clients: set = set()                                        # typed instance var
```

**Exercise goals:** add type hints to functions already written. Don't need to be
able to invent them — just read and write the common ones (str, int, dict, list,
bool, None, | None).

---

#### 1.4 if/else, comparisons, truthiness

Real usage — checking if a value exists before using it:
```python
if not src_ip:
    return event

if threat_qualifies or fraud_qualifies:
    # create a ticket
```

Real usage — inline conditional (ternary):
```python
title_prefix = "High-threat" if threat_qualifies else f"High-fraud (score {fraud})"
```

**Exercise goals:** write if/elif/else, use `and`/`or`/`not`, understand Python
truthiness (empty string, None, 0 are all falsy).

---

#### 1.5 Error handling — try/except/finally

This pattern is everywhere. The service must never crash when one bad message arrives.

Real usage — wrapping every external call:
```python
try:
    result = int(val)
except (TypeError, ValueError):
    return None
```

Real usage — catch anything, log it, keep going:
```python
try:
    await self._enricher.enrich(event)
except Exception as exc:
    logger.warning("enrichment_failed", error=str(exc))
```

**Exercise goals:** write try/except blocks, catch specific exceptions, use finally
for cleanup, understand why swallowing exceptions is sometimes deliberate.

---

### Level 2 — Classes (this is where the real codebase starts to make sense)

#### 2.1 Classes, __init__, self, instance variables

Every major component in the service is a class. Understanding `self` is the unlock.

Real usage — the NatsLogConsumer class:
```python
class NatsLogConsumer:
    def __init__(self, config: Settings) -> None:
        self._config = config      # store the config for later use
        self._running = False      # internal state
        self._pg_pool = None       # will be filled in later

    def stop(self) -> None:
        self._running = False      # method that changes internal state
```

Real usage — the GeoEnricher class:
```python
class GeoEnricher:
    def __init__(self, redis_url: str, http_client: httpx.AsyncClient) -> None:
        self._http_client = http_client   # save the dependency
        self._cache = GeoCache(redis_url) # create a sub-object
```

**Exercise goals:** create a class with `__init__`, store data on `self`, write
methods that read and modify `self` attributes, create instances of the class and
call methods on them.

---

#### 2.2 @staticmethod and @classmethod decorators

Real usage in the codebase:
```python
class NatsLogConsumer:
    @staticmethod
    async def _init_connection(conn) -> None:
        # doesn't use self — pure utility function attached to the class
        await conn.set_type_codec("jsonb", ...)

    @staticmethod
    def _build_target(event: dict) -> str:
        parts = [str(event.get("logline", "")), str(event.get("path", ""))]
        return " ".join(p for p in parts if p)
```

`@staticmethod` means "this function lives on the class but doesn't need `self`."
It's just a regular function that belongs to the class namespace.

**Exercise goals:** add a @staticmethod to a class, understand when to use it vs
a regular method (when you don't need to touch self).

---

#### 2.3 Composition — classes that hold other classes

Real usage — NatsLogConsumer holds references to several other objects:
```python
self._enricher = GeoEnricher(redis_url=..., http_client=...)
self._enrichment_client = EnrichmentClient(mode=..., ...)
self._dispatcher = IntegrationDispatcher(config=..., pool=..., http_client=...)
```

This is called "composition" — building complex behaviour by combining simple classes.
It's the main design pattern in this codebase (as opposed to inheritance).

**Exercise goals:** build two simple classes where one holds a reference to the other
and delegates work to it.

---

### Level 3 — Async Python (the hardest concept, most important for this codebase)

#### 3.1 async def and await basics

Every method that touches the network or database is async. The rule is: if you call
an async function, you must await it, and your function must be async def.

Real usage:
```python
async def enrich(self, event: dict) -> dict:
    src_ip = event.get("src_ip")
    geo = await self._cache.get(src_ip)    # pause here, let other things run
    if geo is None:
        geo = await self._lookup(src_ip)   # pause here too
    return {**event, **geo}
```

**Exercise goals:** write a simple async function that awaits something, understand
the "you must await async functions" rule, understand asyncio.sleep as a stand-in
for real async work.

---

#### 3.2 asyncio.create_task — running things concurrently

Real usage from main.py — starting two background tasks:
```python
_consumer_task = asyncio.create_task(_consumer.start(), name="nats_consumer")
_ws_task = asyncio.create_task(_broadcaster.serve(...), name="ws_broadcaster")
# Both are now running "at the same time" — they take turns at await points
```

**Exercise goals:** create two tasks that run concurrently, observe that they
interleave at await points, understand why this is useful.

---

#### 3.3 async with — async context managers

Real usage — acquiring a database connection from a pool:
```python
async with pool.acquire() as conn:
    await conn.execute("INSERT INTO neural_events ...")
    # conn is automatically released when we leave this block
```

Real usage — starting a WebSocket server:
```python
async with websockets.serve(self.websocket_handler, host, port):
    await self.subscribe_redis()  # runs forever inside the server context
```

**Exercise goals:** write a simple async context manager using @asynccontextmanager,
use `async with` to call it.

---

#### 3.4 Async classes — combining async methods with classes

This is where everything comes together. The WebSocketBroadcaster class has:
- `__init__` (sync, just stores state)
- `broadcast` (async, sends to all clients)
- `serve` (async, runs the server loop forever)

```python
class WebSocketBroadcaster:
    def __init__(self, redis_url: str, channel: str) -> None:
        self._redis_url = redis_url
        self._clients: set = set()            # tracks connected clients

    async def broadcast(self, message: dict) -> None:
        payload = json.dumps(message)
        dead: set = set()
        for ws in list(self._clients):
            try:
                await ws.send(payload)
            except Exception:
                dead.add(ws)
        self._clients -= dead                 # remove disconnected clients

    async def serve(self, host: str, port: int) -> None:
        async with websockets.serve(self.websocket_handler, host, port):
            await self.subscribe_redis()      # runs forever
```

**Exercise goals:** build a small async class from scratch — something like a simple
message queue that accepts messages and delivers them to subscribers.

---

### Level 4 — Real patterns from the pipeline

#### 4.1 Lookup tables (dicts mapping to functions)

One of the most elegant patterns in consumer.py — instead of a giant if/elif chain,
use a dict to map NATS subjects to parser functions:

```python
_TOPIC_PARSERS = {
    "ssh": parse_ssh_log,
    "http": parse_http_log,
    "ftp": parse_ftp_log,
    "mysql": parse_mysql_log,
}

# Usage — call whichever parser matches:
def _dispatch(self, logline, metadata, subject):
    subject_lower = subject.lower()
    for key, parser in _TOPIC_PARSERS.items():
        if key in subject_lower:
            return parser(logline, metadata)
    return None
```

**Exercise goals:** replace an if/elif chain with a dict lookup, understand why
this is cleaner and easier to extend.

---

#### 4.2 Regular expressions

Used in the SSH parser to extract usernames and IPs from raw log lines:

```python
import re

SSH_PATTERNS = [
    re.compile(r"Invalid user (\S+) from ([\d.]+)"),
    re.compile(r"Failed password for (\S+) from ([\d.]+)"),
]

for pattern in SSH_PATTERNS:
    m = pattern.search(logline)
    if m:
        username = m.group(1)   # first capture group
        src_ip = m.group(2)     # second capture group
```

**Exercise goals:** write a regex that extracts parts of a string, use `.search()`,
access capture groups with `.group()`.

---

#### 4.3 Pydantic settings (config loading)

Used in config.py — Pydantic reads environment variables and gives you a typed object:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str             # required — no default, will error if missing
    redis_url: str = "redis://localhost:6379/0"   # optional with default
    enrichment_mode: str = "byok"
    websocket_port: int = 8766

settings = Settings()   # reads from environment + .env file automatically
# Now use: settings.database_url, settings.redis_url, etc.
```

**Exercise goals:** create a simple Pydantic settings class, understand how defaults
work, understand what happens when a required field is missing.

---

#### 4.4 Frozenset and set operations

Used for membership testing — "is this protocol an OT protocol?":

```python
_OT_PROTOCOLS = frozenset({"modbus", "enip", "cip", "dnp3", "s7comm"})

protocol = event.get("protocol", "").lower()
if protocol in _OT_PROTOCOLS:
    return "ot"
```

Also used in WebSocketBroadcaster:
```python
self._clients: set = set()       # mutable set of active connections
dead: set = set()
self._clients -= dead            # remove all dead clients from the set
```

**Exercise goals:** create a set, check membership with `in`, use set operations
(`-=`, `|=`, `&`). Understand the difference between set (mutable) and frozenset
(immutable, hashable).

---

## How to structure the exercises

1. **One concept at a time.** Each exercise should focus on one level/section above.
   Don't mix async into level 1 exercises.

2. **Ground exercises in the AMaze context where possible.** Instead of "write a
   class that represents a car," write "write a class that represents a parsed
   SSH event" or "write a function that checks whether an IP address is private."
   Vivek will be reading this codebase, so the closer the exercises mirror it,
   the better the transfer.

3. **Increment difficulty within each section.** Start with a worked example,
   then a fill-in-the-blank, then write-from-scratch.

4. **Don't require external dependencies until Level 3.** Levels 1-2 should run
   with pure Python (stdlib only). Level 3 needs `asyncio` (stdlib). Level 4
   needs `pydantic` and `re` (both easy to install).

5. **Include expected output** so Vivek can verify his answers himself.

6. **Flag when something in the exercise matches real codebase code.** Vivek is
   motivated by knowing his practice directly maps to what he'll read.

---

## Packages to install for exercises

```bash
pip install pydantic pydantic-settings     # for Level 4 config exercises
# asyncio, re, json are all stdlib — no install needed
```

---

## Final note for the exercise-generating Claude

Vivek is smart and motivated but completely new to writing Python. Keep exercise
descriptions clear and friendly. When introducing a new concept, always show a
minimal working example first before asking him to write anything. Don't assume
he knows what an "iterator" or "generator" is — stick to the patterns listed above
which are the ones he will actually encounter. If he gets stuck, nudge with a hint
rather than giving the answer immediately.
