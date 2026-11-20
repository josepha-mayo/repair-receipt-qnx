"""Verify elapsed-time and coverage controls with signed QNX receipts."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native
from shop_request import CURRENT_RECIPE, RECIPE, request_document


def recording(rows):
    return "6000\n" + "".join(f"{time},800,{speed},{temp}\n" for time, speed, temp in rows)


BURST = recording([
    (0, 0, 101), (1000, 0, 102), (2000, 0, 106), (2003, 0, 107), (2006, 0, 108),
    (3000, 0, 103), (4000, 0, 102), (5000, 0, 101),
])
BELOW_DURATION = recording([
    (0, 0, 100), (1000, 0, 105), (2000, 0, 106), (2999, 0, 107),
    (4000, 0, 102), (5000, 0, 101),
])
AT_DURATION = BELOW_DURATION.replace("2999,800", "3000,800")
INTERLEAVED = recording([(tick * 1000, 20 * (tick % 2), 101) for tick in range(6)])
GAP = recording([(0, 0, 105), (1000, 0, 106), (3500, 0, 108), (4500, 0, 102), (5500, 0, 101)])
MISSING_ROW = recording([(0, 0, 105), (1000, 0, 106), (2000, 0, 107), (3000, 0, 101),
                         (4000, 0, 101), (5000, 0, 101)]).replace("2000,800", "1500,,,\n2000,800")
LEADING_COVERAGE = recording([(tick, 0, 101) for tick in range(2000, 6000, 1000)])
TRAILING_COVERAGE = recording([(tick, 0, 101) for tick in range(0, 5000, 1000)])
OBSERVED_BEFORE_GAP = recording([(0, 0, 105), (1000, 0, 106), (2000, 0, 107), (4500, 0, 101)])
ENGINE_STOP = recording([(0, 0, 105), (1000, 0, 106), (2000, 0, 107), (3000, 0, 108),
                         (4000, 0, 101), (5000, 0, 101)]).replace("2000,800", "2000,0")


def verify(qemu):
    issuer = Issuer(secrets.token_bytes(32))
    cases = (
        ("legacy_burst", RECIPE, BURST, "observed"),
        ("sustained_burst", CURRENT_RECIPE, BURST, "not_observed"),
        ("before_two_seconds", CURRENT_RECIPE, BELOW_DURATION, "not_observed"),
        ("exactly_two_seconds", CURRENT_RECIPE, AT_DURATION, "observed"),
        ("short_idle_segments", CURRENT_RECIPE, INTERLEAVED, "insufficient_evidence"),
        ("interrupted_hot_samples", CURRENT_RECIPE, GAP, "insufficient_evidence"),
        ("explicit_missing_reading", CURRENT_RECIPE, MISSING_ROW, "insufficient_evidence"),
        ("leading_gap_two_seconds", CURRENT_RECIPE, LEADING_COVERAGE, "not_observed"),
        ("leading_gap_over_two_seconds", CURRENT_RECIPE, LEADING_COVERAGE.replace("2000,800", "2001,800"),
         "insufficient_evidence"),
        ("trailing_gap_two_seconds", CURRENT_RECIPE, TRAILING_COVERAGE, "not_observed"),
        ("trailing_gap_over_two_seconds", CURRENT_RECIPE, TRAILING_COVERAGE.replace("4000,800", "3999,800"),
         "insufficient_evidence"),
        ("observed_run_before_gap", CURRENT_RECIPE, OBSERVED_BEFORE_GAP, "observed"),
        ("engine_stop_breaks_hot_run", CURRENT_RECIPE, ENGINE_STOP, "not_observed"),
        ("driver_started_burst", None, BURST, "not_observed"),
        ("driver_started_sustained", None, AT_DURATION, "observed"),
        ("shop_threshold_106", CURRENT_RECIPE, (ROOT / "fixtures/trip-a.csv").read_text(), "observed", 106),
        ("shop_threshold_108", CURRENT_RECIPE, (ROOT / "fixtures/trip-a.csv").read_text(), "not_observed", 108),
    )

    def control(case):
        name, recipe, content, finding, *settings = case
        threshold = settings[0] if settings else None
        ticket = None
        if recipe is None:
            recipe = CURRENT_RECIPE
            expected = {"recipe": recipe, "idle": finding, "moving": "insufficient_evidence"}
        else:
            ticket = request_document("idle", secrets.token_hex(16), recipe, threshold)
            expected = {"recipe": recipe, "request": ticket["id"], "scope": "idle", "idle": finding}
            if threshold is not None:
                expected["thresholdC"] = threshold

        def approve(preview, key):
            if json.loads(preview) != expected or key.decode("ascii") != issuer.public_hex:
                raise RuntimeError("Unexpected QNX preview for " + name)
            return True

        workspace = Path(temporary) / name
        workspace.mkdir()
        path = workspace / "recording.csv"
        path.write_text(content, encoding="ascii")
        receipt = review_native(workspace / "guest", qemu, path, approve, issuer.seed, ticket, image=template)
        issuer.verify_receipt(receipt)
        record = json.loads(receipt)
        if record["claim"] != expected or record["format"] != ("repair-receipt/v2" if ticket else "repair-receipt/v4"):
            raise RuntimeError("Unexpected signed claim for " + name)
        print(f"{name} yielded {finding}", flush=True)
        result = {"control": name, "recipe": recipe, "finding": finding, "signed_format": record["format"]}
        if threshold is not None:
            result["thresholdC"] = threshold
        return result

    with TemporaryDirectory(prefix="rr-duration-proofs-") as temporary:
        template = build_template(Path(temporary) / "template")
        with ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(control, cases))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    results = verify(args.qemu.resolve(strict=True))
    if args.proof:
        args.proof.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
