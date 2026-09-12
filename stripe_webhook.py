"""Verify Stripe webhook signatures without the Stripe SDK.

The official SDK is convenient but heavy. Bundling it into an AWS Lambda
deployment package costs roughly 6.6 MB zipped / 36 MB extracted, which
slows cold starts and nudges you toward layers or container images -- for
what is, in the end, one HMAC comparison.

Verification is a few lines of standard library. This module is that.

No dependencies. Python 3.8+.
"""

import hashlib
import hmac
import time

# Stripe signs `{timestamp}.{raw_body}`. Rejecting old timestamps stops an
# attacker replaying a payload that was validly signed at some point in the past.
DEFAULT_TOLERANCE_SECONDS = 300


def _parse_header(header):
    """Pull the timestamp and every v1 signature out of a Stripe-Signature header.

    Format: `t=1614556800,v1=abc...,v1=def...`

    Note the plural. Stripe sends MORE THAN ONE v1 signature while an endpoint
    secret is being rotated -- one per active secret. Parsing this header into a
    dict silently keeps only the last one, so verification fails for exactly the
    window in which you are rotating. Collect them all and accept any match.
    """
    timestamp = None
    signatures = []
    for part in header.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    return timestamp, signatures


def verify(raw_body, signature_header, secret, tolerance=DEFAULT_TOLERANCE_SECONDS, now=None):
    """Return True if `raw_body` carries a valid, non-stale Stripe signature.

    raw_body         the request body as sent, bytes or str. Must be the EXACT
                     bytes Stripe signed -- do not parse and re-serialise the
                     JSON first, or the signature will never match.
    signature_header the `Stripe-Signature` request header.
    secret           the endpoint's signing secret (`whsec_...`).
    tolerance        max age in seconds; 0 or None disables the check.
    now              current unix time; injectable for tests.

    Returns a bool rather than raising, so the caller must actually look at it.
    """
    if not secret or not signature_header or raw_body is None:
        return False

    if isinstance(raw_body, str):
        raw_body = raw_body.encode("utf-8")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    timestamp, signatures = _parse_header(signature_header)
    if not timestamp or not signatures:
        return False

    if tolerance:
        try:
            age = abs((now if now is not None else time.time()) - int(timestamp))
        except (TypeError, ValueError):
            return False
        if age > tolerance:
            return False

    expected = hmac.new(
        secret,
        timestamp.encode("utf-8") + b"." + raw_body,
        hashlib.sha256,
    ).hexdigest()

    # compare_digest is constant-time: a plain `==` leaks how much of the
    # signature matched, which is enough to forge one byte at a time.
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)
