"""Verify the signed optional startup window with a native QNX guest."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native
from shop_request import (
    CURRENT_RECIPE, DEFAULT_THRESHOLD_C, STARTUP_RECIPE, UPLOADED_SOURCE,
    canonical, request_document, verification_packet,
)


OPENING = "5000\n0,,,\n1000,800,0,101\n2000,800,0,101\n3000,800,0,101\n4000,800,0,101\n"
AFTER_FIRST = OPENING.replace("0,,,", "0,800,0,101\n500,,,")
LATER_GAP = OPENING.replace("2000,800,0,101\n3000,800,0,101\n", "")
ROAD = ROOT / "fixtures/kit-july-27.csv"
CASES = [
    ("strict-request", OPENING, CURRENT_RECIPE, "idle", None, {"idle": "insufficient_evidence"}),
    ("exact-one-second", OPENING, STARTUP_RECIPE, "idle", None, {"idle": "not_observed"}),
    ("short-opening-gap", OPENING.replace("1000,800", "250,800"), STARTUP_RECIPE, "idle", None,
     {"idle": "not_observed"}),
    ("complete-opening", OPENING.replace("0,,,", "0,800,0,101"), STARTUP_RECIPE, "idle", None,
     {"idle": "not_observed"}),
    ("configured-threshold", OPENING, STARTUP_RECIPE, "idle", 101, {"idle": "observed"}),
    ("one-millisecond-over", OPENING.replace("1000,800", "1001,800"), STARTUP_RECIPE, "idle", None,
     {"idle": "insufficient_evidence"}),
    ("gap-after-first-complete", AFTER_FIRST, STARTUP_RECIPE, "idle", None, {"idle": "insufficient_evidence"}),
    ("later-cadence-break", LATER_GAP, STARTUP_RECIPE, "idle", None, {"idle": "insufficient_evidence"}),
    ("positive-after-gap", AFTER_FIRST, STARTUP_RECIPE, "idle", 101, {"idle": "observed"}),
    ("road-strict-scope", ROAD, CURRENT_RECIPE, "both", 95,
     {"idle": "observed", "moving": "insufficient_evidence"}),
    ("road-startup-scope", ROAD, STARTUP_RECIPE, "both", 95, {"idle": "observed", "moving": "not_observed"}),
]
WINDOW_MS = {
    "exact-one-second": 1000, "short-opening-gap": 250, "complete-opening": 0, "configured-threshold": 1000,
    "one-millisecond-over": 0, "gap-after-first-complete": 0, "later-cadence-break": 1000,
    "positive-after-gap": 0, "road-startup-scope": 210,
}


def verify(qemu, packet_zip=None):
    issuer = Issuer(secrets.token_bytes(32))
    comparison = request_document("idle", secrets.token_hex(16), STARTUP_RECIPE)
    with TemporaryDirectory(prefix="rr-startup-window-") as tmp:
        directory = Path(tmp)
        template = build_template(directory / "template")

        def run(case):
            name, recording, recipe, scope, threshold, outcomes = case
            same_request = name in ("exact-one-second", "short-opening-gap", "complete-opening")
            request = comparison if same_request else request_document(scope, secrets.token_hex(16), recipe, threshold)
            expected = {"recipe": recipe, "source": UPLOADED_SOURCE, "request": request["id"],
                        "scope": scope, **outcomes}
            if threshold is not None:
                expected["thresholdC"] = threshold

            def approve(preview, key):
                if json.loads(preview) != expected or key.decode("ascii") != issuer.public_hex:
                    raise RuntimeError(f"Unexpected preview in {name}.")
                return True

            if isinstance(recording, str):
                path = directory / f"{name}.csv"
                path.write_text(recording, encoding="ascii", newline="\n")
            else:
                path = recording
            guest = directory / name
            reported_windows = []
            receipt = review_native(guest, qemu, path, approve, issuer.seed, request, image=template,
                                    source=UPLOADED_SOURCE, on_startup_window=reported_windows.append)
            issuer.verify_receipt(receipt)
            record = json.loads(receipt)
            if record["format"] != "repair-receipt/v5" or record["claim"] != expected:
                raise RuntimeError(f"Unexpected signed claim in {name}.")
            expected_windows = [WINDOW_MS[name]] if name in WINDOW_MS else []
            diagnostics = (guest / "serial.log").read_bytes()
            startup_lines = [line for line in diagnostics.splitlines() if b"RR_STARTUP_WINDOW" in line]
            redacted = [b"RR_STARTUP_WINDOW [driver-only interval]"] if expected_windows else []
            if reported_windows != expected_windows or startup_lines != redacted:
                raise RuntimeError(f"Private startup window report or redaction failed in {name}.")
            if b"RR_STARTUP_WINDOW" in (guest / "console.log").read_bytes():
                raise RuntimeError(f"The startup window reached the console log in {name}.")
            result = {"case": name, "recipe": recipe, "scope": scope,
                      "thresholdC": threshold if threshold is not None else DEFAULT_THRESHOLD_C, "findings": outcomes}
            packet = verification_packet(request, receipt.decode("ascii"), issuer.fingerprint) if recording == ROAD else None
            return result, packet, receipt

        with ThreadPoolExecutor(max_workers=2) as pool:
            runs = list(pool.map(run, CASES))
    comparable = {receipt for result, _, receipt in runs
                  if result["case"] in ("exact-one-second", "short-opening-gap", "complete-opening")}
    if len(comparable) != 1:
        raise RuntimeError("The private startup interval changed the signed receipt.")
    if packet_zip:
        with ZipFile(packet_zip, "x", compression=ZIP_DEFLATED) as archive:
            archive.writestr("issuer.json", canonical({"format": "repair-receipt-issuer/v1", "ed25519": issuer.public_hex}))
            for result, packet, _ in runs:
                if packet is not None:
                    archive.writestr(result["case"] + ".json", canonical(packet))
    return [result for result, _, _ in runs]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--write-road-packets", type=Path, help="save a new ZIP with the two July 27 packets and public key")
    args = parser.parse_args()
    print(json.dumps(verify(args.qemu.resolve(strict=True), args.write_road_packets), indent=2))
