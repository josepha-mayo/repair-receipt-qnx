"""Check consent at the exact expiry boundary without waiting five minutes."""

from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from issuer_store import Issuer
import live


class ConsentDeadline(unittest.TestCase):
    def review_at(self, instant, action):
        review = live.Review(None, Issuer(bytes(32)), None)
        review.owner = "driver"
        review.state = {"stage": "booting", "job": "test-job"}
        now = 0.0
        result = None

        def arrive(timeout):
            nonlocal now, result
            self.assertEqual(timeout, live.CONSENT_SECONDS)
            now = instant
            result = action(review)

        review.response = SimpleNamespace(wait=arrive, set=lambda: None)
        with patch.object(live, "time", SimpleNamespace(monotonic=lambda: now)):
            shared = review.wait_for_decision(b'{"idle":"insufficient_evidence"}',
                                              review.issuer.public_hex.encode("ascii"), Event(), {"idle": 1})
            return shared, result, review.snapshot("driver")

    def test_approval_before_the_deadline(self):
        shared, accepted, owner = self.review_at(live.CONSENT_SECONDS - 0.001,
            lambda review: review.decide("driver", "test-job", "share"))
        self.assertTrue(shared)
        self.assertTrue(accepted)
        self.assertIn("claim", owner)

    def test_expiry_withholds_consent_and_discards_the_preview(self):
        deadline = live.CONSENT_SECONDS
        retained = {"stage": "finishing", "job": "test-job"}
        for instant, action, expected in (
            (deadline, lambda review: review.decide("driver", "test-job", "share"), False),
            (deadline + 0.001, lambda review: review.decide("driver", "test-job", "share"), False),
            (deadline, lambda review: review.snapshot("driver"), retained),
            (deadline, lambda review: None, None),
        ):
            with self.subTest(instant=instant, expected=expected):
                shared, result, owner = self.review_at(instant, action)
                self.assertFalse(shared)
                self.assertEqual(result, expected)
                self.assertEqual(owner, retained)


if __name__ == "__main__":
    unittest.main()
