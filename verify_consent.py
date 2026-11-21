"""Check consent at the exact expiry boundary without waiting five minutes."""

from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from issuer_store import Issuer
import live


class ConsentDeadline(unittest.TestCase):
    def review_at(self, instant, action, *, prior_owner="driver", request_id="follow-up"):
        review = live.Review(None, Issuer(bytes(32)), None)
        review.owner = "driver"
        review.state = {"stage": "booting", "job": "test-job"}
        digest = bytes(32)
        review.last_import = (prior_owner, digest, "original")
        now = 0.0
        result = None
        notice = None

        def arrive(timeout):
            nonlocal now, result, notice
            self.assertEqual(timeout, live.CONSENT_SECONDS)
            notice = review.snapshot("driver").get("reusedRecording")
            now = instant
            result = action(review)

        review.response = SimpleNamespace(wait=arrive, set=lambda: None)
        with patch.object(live, "time", SimpleNamespace(monotonic=lambda: now)):
            shared = review.wait_for_decision(b'{"idle":"insufficient_evidence"}',
                                              review.issuer.public_hex.encode("ascii"), Event(), {"idle": 1},
                                              (digest, request_id))
            return shared, result, review.snapshot("driver"), notice

    def test_approval_before_the_deadline(self):
        shared, accepted, owner, notice = self.review_at(live.CONSENT_SECONDS - 0.001,
            lambda review: review.decide("driver", "test-job", "share"))
        self.assertTrue(shared)
        self.assertTrue(accepted)
        self.assertIn("claim", owner)
        self.assertIs(notice, True)
        self.assertNotIn("reusedRecording", owner)

    def test_reuse_notice_is_scoped_to_the_same_driver_and_a_new_request(self):
        for options in ({"prior_owner": "another-driver"}, {"request_id": "original"}):
            with self.subTest(options=options):
                _, _, _, notice = self.review_at(live.CONSENT_SECONDS - 1,
                    lambda review: review.decide("driver", "test-job", "decline"), **options)
                self.assertIsNone(notice)

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
                shared, result, owner, notice = self.review_at(instant, action)
                self.assertFalse(shared)
                self.assertIs(notice, True)
                self.assertEqual(result, expected)
                self.assertEqual(owner, retained)


if __name__ == "__main__":
    unittest.main()
