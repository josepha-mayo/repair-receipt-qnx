"""Check consent expiry and recovery from a failed QNX image build."""

from concurrent.futures import Future
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from issuer_store import Issuer
import live


class ConsentDeadline(unittest.TestCase):
    def review_at(self, instant, action, *, prior_owner="driver", request_id="follow-up", startup_excluded_ms=None):
        review = live.Review(None, Issuer(bytes(32)), Future)
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
            self.assertEqual(review.snapshot("driver").get("startupExcludedMs"), startup_excluded_ms)
            self.assertNotIn("startupExcludedMs", review.snapshot("different-driver"))
            now = instant
            result = action(review)

        review.response = SimpleNamespace(wait=arrive, set=lambda: None)
        with patch.object(live, "time", SimpleNamespace(monotonic=lambda: now)):
            shared = review.wait_for_decision(b'{"idle":"insufficient_evidence"}',
                                              review.issuer.public_hex.encode("ascii"), Event(), {"idle": 1},
                                              (digest, request_id), startup_excluded_ms=startup_excluded_ms)
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

    def test_startup_window_is_private_and_ends_with_consent(self):
        for duration in (0, 210):
            for offset, choice in ((-1, "share"), (-1, "decline"), (0, "share")):
                with self.subTest(duration=duration, offset=offset, choice=choice):
                    _, _, owner, _ = self.review_at(live.CONSENT_SECONDS + offset,
                        lambda review: review.decide("driver", "test-job", choice), startup_excluded_ms=duration)
                    self.assertNotIn("startupExcludedMs", owner)

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

    def test_failed_preparation_does_not_replay_a_queued_recording(self):
        original, retry = Future(), Future()
        builds = iter((original, retry))
        review = live.Review(None, Issuer(bytes(32)), lambda: next(builds))
        self.assertTrue(review.start("driver", b"queued recording", None))
        original.set_exception(ValueError("simulated image builder failure"))
        review.worker.join(timeout=2)
        self.assertFalse(review.worker.is_alive())
        self.assertIn("QNX preparation failed", review.snapshot("driver")["message"])
        self.assertFalse(review.start("driver", b"another recording", None))
        self.assertTrue(review.retry_preparation())
        self.assertEqual(review.snapshot("driver"), {"stage": "ready"})
        self.assertEqual(review.template_status(), "building")
        self.assertFalse(review.retry_preparation())
        retry.set_result("prepared guest")
        self.assertEqual(review.template_status(), "ready")
        self.assertFalse(review.retry_preparation())
        review.close()


if __name__ == "__main__":
    unittest.main()
