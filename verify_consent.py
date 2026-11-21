"""Check consent expiry and recovery from a failed QNX image build."""

from concurrent.futures import Future
from threading import Event
from time import monotonic, sleep
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from issuer_store import Issuer
import live
from run_qnx import decode_coverage_detail
from shop_request import canonical, request_document, verification_packet


class ConsentDeadline(unittest.TestCase):
    def review_at(self, instant, action, *, prior_owner="driver", request_id="follow-up", startup_excluded_ms=None,
                  prior_rule=None, previous_rule=None, coverage_detail=None):
        review = live.Review(None, Issuer(bytes(32)), Future)
        review.owner = "driver"
        review.state = {"stage": "booting", "job": "test-job"}
        digest = bytes(32)
        review.recent_uploads[(prior_owner, digest)] = ("original", prior_rule)
        now = 0.0
        result = None
        notice = None

        def arrive(timeout):
            nonlocal now, result, notice
            self.assertEqual(timeout, live.CONSENT_SECONDS)
            notice = review.snapshot("driver").get("reusedRecording")
            self.assertEqual(review.snapshot("driver").get("startupExcludedMs"), startup_excluded_ms)
            self.assertEqual(review.snapshot("driver").get("previousRecordingRule"), previous_rule)
            self.assertNotIn("previousRecordingRule", review.snapshot("different-driver"))
            self.assertEqual(review.snapshot("driver").get("coverageDetail"), coverage_detail)
            self.assertNotIn("coverageDetail", review.snapshot("different-driver"))
            self.assertNotIn("startupExcludedMs", review.snapshot("different-driver"))
            now = instant
            result = action(review)

        review.response = SimpleNamespace(wait=arrive, set=lambda: None)
        with patch.object(live, "time", SimpleNamespace(monotonic=lambda: now)):
            preview = b'{"recipe":"coolant-duration-demo/v2","idle":"insufficient_evidence"}'
            shared = review.wait_for_decision(preview,
                                              review.issuer.public_hex.encode("ascii"), Event(), {"idle": 1},
                                              (digest, request_id), startup_excluded_ms=startup_excluded_ms,
                                              coverage_detail=coverage_detail)
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

    def test_previous_rule_is_private_and_cleared_on_decision_or_expiry(self):
        prior = {"scope": "idle", "thresholdC": 95, "recipe": live.CURRENT_RECIPE}
        for offset, choice in ((-1, "share"), (-1, "decline"), (0, "share")):
            with self.subTest(offset=offset, choice=choice):
                _, _, owner, _ = self.review_at(live.CONSENT_SECONDS + offset,
                    lambda review: review.decide("driver", "test-job", choice), prior_rule=prior, previous_rule=prior)
                self.assertNotIn("previousRecordingRule", owner)
        for options in ({"prior_owner": "another-driver", "prior_rule": prior},
                        {"prior_rule": {"scope": "both", "thresholdC": 105, "recipe": live.CURRENT_RECIPE}}):
            with self.subTest(options=options):
                self.review_at(live.CONSENT_SECONDS - 1,
                    lambda review: review.decide("driver", "test-job", "decline"), **options)

    def test_recent_upload_history_has_a_fixed_limit(self):
        review = live.Review(None, Issuer(bytes(32)), Future)
        review.owner = "driver"
        claim = {"recipe": live.CURRENT_RECIPE}
        keys = [index.to_bytes(32, "big") for index in range(live.RECENT_UPLOAD_LIMIT + 1)]
        for digest in keys:
            review._note_upload((digest, "request"), claim)
        self.assertEqual(len(review.recent_uploads), live.RECENT_UPLOAD_LIMIT)
        self.assertNotIn(("driver", keys[0]), review.recent_uploads)
        self.assertIn(("driver", keys[-1]), review.recent_uploads)

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

    def test_coverage_details_are_private_and_end_with_consent(self):
        for offset, choice in ((-1, "share"), (-1, "decline"), (0, "share")):
            with self.subTest(offset=offset, choice=choice):
                _, _, owner, _ = self.review_at(live.CONSENT_SECONDS + offset,
                    lambda review: review.decide("driver", "test-job", choice), coverage_detail={"firstGapMs": 0})
                self.assertNotIn("coverageDetail", owner)

    def test_coverage_detail_must_match_the_reason_and_requested_condition(self):
        self.assertEqual(decode_coverage_detail((513995, 1500, -2), {"idle": 3}),
                         {"firstGapMs": 513995, "idleSpanMs": 1500})
        for fields, coverage in (((0, -2, -2), {"idle": 2}),
                                 ((-1, -2, 1500), {"idle": 2}),
                                 ((-1, 2000, -2), {"idle": 2})):
            with self.subTest(fields=fields, coverage=coverage), self.assertRaises(RuntimeError):
                decode_coverage_detail(fields, coverage)

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

    def test_displaced_approval_is_only_recoverable_by_its_driver(self):
        template = Future()
        template.set_result("prepared guest")
        issuer = Issuer(bytes(32))
        review = live.Review(None, issuer, lambda: template)
        request = request_document("idle", "0" * 32, live.CURRENT_RECIPE)
        claim = {"recipe": live.CURRENT_RECIPE, "source": live.DEMO_SOURCE, "request": request["id"],
                 "scope": "idle", "idle": "observed"}
        payload = canonical(claim).encode("ascii")
        signature = Ed25519PrivateKey.from_private_bytes(issuer.seed).sign(b"Repair Receipt v5\n" + payload).hex()
        receipt = canonical({"format": "repair-receipt/v5", "claim": claim, "signature": signature})
        packet = verification_packet(request, receipt, issuer.fingerprint)

        def evaluate(_workspace, _qemu, _recording, decide, *_args, **kwargs):
            kwargs["on_coverage"]({"idle": 1})
            kwargs["on_coverage_detail"]({"firstGapMs": 811})
            return receipt.encode("ascii") if decide(payload, issuer.public_hex.encode("ascii")) else None

        def waiting(driver):
            deadline = monotonic() + 3
            while monotonic() < deadline:
                state = review.snapshot(driver)
                if state["stage"] == "review":
                    return state["job"]
                sleep(0.01)
            self.fail("The driver did not reach consent.")

        with patch.object(live, "review_native", evaluate):
            try:
                self.assertTrue(review.start("first", b"first sample", request, source=live.DEMO_SOURCE))
                job = waiting("first")
                self.assertTrue(review.decide("first", job, "share"))
                review.worker.join(timeout=3)
                self.assertFalse(review.worker.is_alive())
                self.assertEqual(review.snapshot("first")["packet"], packet)
                self.assertTrue(review.start("second", b"second sample", request, source=live.DEMO_SOURCE))
                next_job = waiting("second")
                saved = {"stage": "shared", "job": job, "claim": claim, "issuer": issuer.public_hex,
                         "receipt": receipt, "packet": packet}
                self.assertEqual(review.snapshot("first"), {**saved, "otherReviewActive": True})
                self.assertEqual(review.snapshot("third"), {"stage": "occupied"})
                self.assertFalse(review.decide("first", next_job, "share"))
                self.assertFalse(review.start("first", b"blocked", request))
                self.assertTrue(review.decide("second", next_job, "decline"))
                review.worker.join(timeout=3)
                self.assertFalse(review.worker.is_alive())
                self.assertEqual(review.snapshot("first"), {**saved, "otherReviewActive": False})
                self.assertNotIn("receipt", review.snapshot("second"))
                self.assertTrue(review.start("first", b"new", request))
                self.assertNotIn("receipt", review.snapshot("first"))
            finally:
                review.close()


if __name__ == "__main__":
    unittest.main()
