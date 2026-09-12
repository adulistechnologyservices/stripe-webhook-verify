"""Run with: python3 -m unittest -v  (no test framework needed)"""

import hashlib
import hmac
import time
import unittest

from stripe_webhook import verify

SECRET = "whsec_test_secret"
BODY = '{"id":"evt_1","type":"checkout.session.completed"}'


def sign(body, secret=SECRET, timestamp=None, scheme="v1"):
    timestamp = str(int(timestamp if timestamp is not None else time.time()))
    sig = hmac.new(
        secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},{scheme}={sig}"


class VerifyTests(unittest.TestCase):
    def test_valid_signature_passes(self):
        self.assertTrue(verify(BODY, sign(BODY), SECRET))

    def test_bytes_body_passes(self):
        self.assertTrue(verify(BODY.encode(), sign(BODY), SECRET))

    def test_missing_header_fails(self):
        self.assertFalse(verify(BODY, "", SECRET))
        self.assertFalse(verify(BODY, None, SECRET))

    def test_missing_secret_fails(self):
        self.assertFalse(verify(BODY, sign(BODY), ""))

    def test_forged_signature_fails(self):
        header = f"t={int(time.time())},v1={'a' * 64}"
        self.assertFalse(verify(BODY, header, SECRET))

    def test_tampered_body_fails(self):
        header = sign(BODY)
        self.assertFalse(verify(BODY.replace("evt_1", "evt_2"), header, SECRET))

    def test_wrong_secret_fails(self):
        self.assertFalse(verify(BODY, sign(BODY, secret="whsec_other"), SECRET))

    def test_replayed_old_timestamp_fails(self):
        old = time.time() - 3600
        self.assertFalse(verify(BODY, sign(BODY, timestamp=old), SECRET))

    def test_old_timestamp_accepted_when_tolerance_disabled(self):
        old = time.time() - 3600
        self.assertTrue(verify(BODY, sign(BODY, timestamp=old), SECRET, tolerance=0))

    def test_future_timestamp_outside_tolerance_fails(self):
        future = time.time() + 3600
        self.assertFalse(verify(BODY, sign(BODY, timestamp=future), SECRET))

    def test_non_numeric_timestamp_fails(self):
        self.assertFalse(verify(BODY, "t=notanumber,v1=" + "a" * 64, SECRET))

    def test_unknown_scheme_alone_fails(self):
        # v0 is Stripe's test-mode-only scheme; never accept it as proof
        self.assertFalse(verify(BODY, sign(BODY, scheme="v0"), SECRET))

    def test_multiple_v1_signatures_during_secret_rotation(self):
        """Stripe sends one v1 per active secret while rotating. Any match wins."""
        ts = str(int(time.time()))
        good = hmac.new(
            SECRET.encode(), f"{ts}.{BODY}".encode(), hashlib.sha256
        ).hexdigest()
        header = f"t={ts},v1={'b' * 64},v1={good}"
        self.assertTrue(verify(BODY, header, SECRET))
        # and the reverse order, to prove it is not just reading the last one
        self.assertTrue(verify(BODY, f"t={ts},v1={good},v1={'b' * 64}", SECRET))

    def test_malformed_header_fragments_ignored(self):
        ts = str(int(time.time()))
        good = hmac.new(
            SECRET.encode(), f"{ts}.{BODY}".encode(), hashlib.sha256
        ).hexdigest()
        self.assertTrue(verify(BODY, f"garbage,t={ts},,v1={good}", SECRET))


if __name__ == "__main__":
    unittest.main()
