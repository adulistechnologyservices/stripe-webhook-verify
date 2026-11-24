# stripe-webhook-verify

Verify Stripe webhook signatures in AWS Lambda without the Stripe SDK.

No dependencies. Python 3.8+. The whole thing is one file and about 60 lines.

## Why

The official Stripe Python library is the right default in most places. In a
Lambda it is less comfortable: bundling it costs roughly **6.6 MB zipped /
36 MB extracted**, which slows cold starts and pushes you toward layers or
container images.

If all you need from it is `Webhook.construct_event`, that is one HMAC-SHA256
and a timestamp check — a few lines of standard library.

Use the SDK if you also call the Stripe API from the same function. This is for
the common case where a Lambda exists only to receive webhooks.

## Use

```python
from stripe_webhook import verify

if not verify(raw_body, request.headers["Stripe-Signature"], WEBHOOK_SECRET):
    return 400
```

`verify()` returns a bool rather than raising, so the caller has to look at it.

See `handler_example.py` for a complete API Gateway (HTTP API v2.0) handler.

## What it checks

- **HMAC-SHA256** over `{timestamp}.{raw_body}`, keyed with the endpoint secret.
- **Constant-time comparison** via `hmac.compare_digest`. A plain `==` leaks how
  many leading bytes matched, which is enough to forge a signature byte by byte.
- **Timestamp tolerance**, 300s by default. Without it, a payload that was validly
  signed at any point in the past can be replayed forever.
- **Every `v1` signature in the header, not just one.** See below.

## Three things that are easy to get wrong

**Stripe can send more than one signature.** During an endpoint secret rotation
the header carries one `v1` per active secret:

```
t=1614556800,v1=5257a8...,v1=aa4b8c...
```

Parsing that header into a dict keeps only the last one, so verification fails
for exactly the window you are rotating in — the worst possible time to find out.
This library collects every `v1` and accepts any match.

**Verify the raw bytes.** The signature covers exactly what Stripe sent. If you
`json.loads` the body and re-serialise it before verifying, key order and
whitespace shift and the signature will never match. Decode base64 if your
gateway applied it; do nothing else.

**Deliveries are at-least-once.** The same event id can arrive twice. Key your
writes on `event["id"]` and make the handler idempotent.

## Tests

```
python3 -m unittest -v
```

14 tests, no test framework required — valid, forged, tampered, wrong secret,
missing header, replayed timestamp, future timestamp, non-numeric timestamp,
`v0`-only, multiple `v1` during rotation, malformed fragments.

## Licence

MIT — see [LICENSE](LICENSE).

Built and used in production by [ATS — Adulis Technology Services](https://adulistechnologyservices.com).
