"""API gateway events + signed webhooks (Phase 5).

Two pieces:

  * :class:`EventBus` — every case-relevant happening becomes a structured
    event (action.completed, approval.requested, workflow.*, …), persisted
    in the case DB and delivered to subscribed webhooks.
  * :class:`WebhookDispatcher` — HTTP POST with an ``X-RP-Signature``
    HMAC-SHA256 header over ``timestamp.body`` keyed by the webhook secret.
    Receivers verify authenticity with the shared secret; replays are
    bounded by the timestamp check on the receiver side.

Delivery is best-effort with a bounded retry count; failed endpoints are
recorded in the delivery log so operators can inspect them. No event ever
carries secret material (redaction applies before emission).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid

from ..core.errors import UsageError
from ..core.redact import redact
from ..evidence.audit import AuditChain
from ..storage.database import Database

EVENT_SCHEMA_VERSION = 1
MAX_WEBHOOK_RETRIES = 2
WEBHOOK_TIMEOUT = 10


def emit_event(
    db: Database,
    case_id: str,
    event_type: str,
    payload: dict,
    *,
    actor: str = "system",
) -> dict:
    """Persist one structured event (redacted) and return it."""
    event = {
        "id": f"evt_{uuid.uuid4().hex[:12]}",
        "schema_version": EVENT_SCHEMA_VERSION,
        "case_id": case_id,
        "type": event_type,
        "actor": actor,
        "payload": json.loads(redact(json.dumps(payload, default=str))),
        "at": time.time(),
    }
    db.set_meta(f"event:{event['id']}", json.dumps(event, sort_keys=True))
    index = json.loads(db.get_meta("events") or "[]")
    index.append(event["id"])
    # keep the index bounded: the newest 500 events
    db.set_meta("events", json.dumps(index[-500:]))
    return event


def list_events(db: Database, case_id: str, *, limit: int = 50) -> list[dict]:
    ids = json.loads(db.get_meta("events") or "[]")
    events = []
    for event_id in reversed(ids[-limit:]):
        raw = db.get_meta(f"event:{event_id}")
        if raw:
            event = json.loads(raw)
            if event.get("case_id") == case_id:
                events.append(event)
    return events


def register_webhook(db: Database, case_id: str, *, url: str, secret: str,
                     events: list[str] | None = None) -> dict:
    if not url.startswith(("http://", "https://")):
        raise UsageError(
            f"Webhook URL must be http(s): {url}",
            action="Use an https endpoint for production webhooks.")
    hook_id = f"whk_{uuid.uuid4().hex[:12]}"
    db.set_meta(f"webhook:{hook_id}", json.dumps({
        "id": hook_id, "case_id": case_id, "url": url,
        "secret": secret, "events": sorted(set(events or [])) or ["*"],
        "created_at": time.time(),
    }, sort_keys=True))
    return {"id": hook_id, "url": url, "events": sorted(set(events or [])) or ["*"]}


def list_webhooks(db: Database, case_id: str) -> list[dict]:
    hooks = []
    for key, value in db.iter_meta():
        if key.startswith("webhook:"):
            data = json.loads(value)
            if data["case_id"] == case_id:
                hooks.append({k: v for k, v in data.items() if k != "secret"})
    return hooks


def sign_payload(secret: str, body: bytes, timestamp: str) -> str:
    """X-RP-Signature value: v1=<hex hmac over timestamp.body>."""
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode() + b"." + body,
                   hashlib.sha256)
    return f"v1={mac.hexdigest()}"


def dispatch_event(db: Database, event: dict, *, post=None) -> list[dict]:
    """Deliver one event to every matching webhook; return delivery records."""
    poster = post or _default_post
    deliveries = []
    for key, value in db.iter_meta():
        if not key.startswith("webhook:"):
            continue
        hook = json.loads(value)
        if hook["case_id"] != event["case_id"]:
            continue
        if "*" not in hook["events"] and event["type"] not in hook["events"]:
            continue
        body = json.dumps(event, sort_keys=True).encode()
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "X-RP-Signature": sign_payload(hook["secret"], body, timestamp),
            "X-RP-Timestamp": timestamp,
            "X-RP-Event": event["type"],
        }
        attempts = 0
        status, error = 0, ""
        while attempts <= MAX_WEBHOOK_RETRIES:
            attempts += 1
            status, error = poster(hook["url"], body, headers)
            if status == 200:
                break
        deliveries.append({
            "webhook_id": hook["id"], "url": hook["url"],
            "event": event["type"], "status": status,
            "attempts": attempts, "ok": status == 200, "error": error[:200],
        })
    if deliveries:
        db.set_meta(f"webhook_delivery:{event['id']}",
                    json.dumps(deliveries, sort_keys=True))
    return deliveries


def _default_post(url: str, body: bytes, headers: dict) -> tuple[int, str]:
    try:
        request = urllib.request.Request(url, data=body, headers=headers,
                                         method="POST")
        with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT) as response:
            return response.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc)
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(exc)


class ApiGateway:
    """Read-only HTTP API over one case (token-gated, stdlib-only).

    Endpoints:
      GET /            → service banner
      GET /healthz     → liveness
      GET /state       → case summary (claims, evidence stats, audit head)
      GET /events      → recent structured events

    Authentication: ``Authorization: Bearer <token>`` where the token is the
    hex SHA-256 of the configured API secret; a case with no configured
    secret serves nothing (fail closed).
    """

    def __init__(self, db: Database, case_id: str, *, token: str = "") -> None:
        self._db = db
        self.case_id = case_id
        self._token = token

    def handle(self, method: str, path: str, authorization: str = "") -> tuple[int, dict]:
        if method != "GET":
            return 405, {"error": "method not allowed",
                         "allowed": ["GET"], "what": "read-only gateway"}
        if not self._token:
            return 503, {"error": "API disabled",
                         "action": "Set api.token in config or RP_API_TOKEN env."}
        supplied = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied, self._token):
            return 401, {"error": "unauthorized"}
        if path in {"/", ""}:
            return 200, {"service": "rebel-profiler api", "version": 1,
                         "case_id": self.case_id}
        if path == "/healthz":
            return 200, {"ok": True}
        if path == "/state":
            claims = self._db.claims_for(self.case_id)
            return 200, {
                "case_id": self.case_id,
                "claims": len(claims),
                "evidence": len(self._db.conn.execute(
                    "SELECT 1 FROM evidence_records WHERE case_id = ?",
                    (self.case_id,)).fetchall()),
                "audit_head": self._db.conn.execute(
                    "SELECT hash FROM audit_events WHERE case_id = ?"
                    " ORDER BY seq DESC LIMIT 1", (self.case_id,)).fetchone(),
            }
        if path == "/events":
            return 200, {"events": list_events(self._db, self.case_id, limit=50)}
        return 404, {"error": "not found",
                     "endpoints": ["/", "/healthz", "/state", "/events"]}
