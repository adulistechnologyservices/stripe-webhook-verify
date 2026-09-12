"""Minimal AWS Lambda handler behind API Gateway (HTTP API, payload v2.0).

Deploy as-is to see it work, then replace the body of `process()`.
Set STRIPE_WEBHOOK_SECRET in the function's environment.
"""

import base64
import json
import os

from stripe_webhook import verify

WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


def handler(event, context):
    # The signature covers the exact bytes Stripe sent. API Gateway may base64
    # the body; decode, but never json.loads-and-re-dump before verifying --
    # key order and whitespace change and the signature will never match.
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")

    # Header names arrive lower-cased on HTTP APIs, but do not count on it.
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    signature = headers.get("stripe-signature", "")

    if not verify(raw_body, signature, WEBHOOK_SECRET):
        # 400 tells Stripe the delivery failed; it will retry with backoff.
        return {"statusCode": 400, "body": "invalid signature"}

    process(json.loads(raw_body))

    # Return 2xx promptly. Stripe times out at 30s at the time of writing and
    # retries on timeout, so push slow work onto a queue rather than blocking.
    return {"statusCode": 200, "body": "ok"}


def process(event_obj):
    event_type = event_obj.get("type")
    obj = (event_obj.get("data") or {}).get("object") or {}
    print(f"verified {event_type} id={event_obj.get('id')} object={obj.get('id')}")
    # Handle the events you care about, e.g.
    #   checkout.session.completed, invoice.paid,
    #   invoice.payment_failed, customer.subscription.deleted
    #
    # Webhook deliveries are at-least-once: the same event id can arrive more
    # than once. Make this idempotent -- key your writes on event_obj["id"].
