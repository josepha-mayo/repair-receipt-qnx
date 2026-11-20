"""Reproduce QNX OBD-II bench capture and failure controls."""

import argparse
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time

from issuer_store import Issuer
from run_qnx import build_template, review_native
from shop_request import BENCH_SOURCE, CURRENT_RECIPE


def verify(qemu):
    traces = []
    issuer = Issuer(secrets.token_bytes(32))
    ticket = {
        "format": "repair-receipt-request/v1", "recipe": CURRENT_RECIPE,
        "scope": "both", "id": secrets.token_hex(16),
    }
    controls = (
        ("normal", ("observed", "not_observed"), b"RR_CAPTURE_COMPLETE 7 0"),
        ("gapped", ("insufficient_evidence", "insufficient_evidence"), b"RR_CAPTURE_COMPLETE 5 2"),
        ("motion-change", ("insufficient_evidence", "insufficient_evidence"), b"RR_CAPTURE_COMPLETE 6 1"),
        ("late-reply", ("insufficient_evidence", "insufficient_evidence"), b"RR_CAPTURE_COMPLETE 2 1"),
        ("link-loss", ("observed", "insufficient_evidence"), b"RR_CAPTURE_COMPLETE 4 1"),
        ("setup-failure", None, b"RR_INVALID adapter_unavailable"),
    )
    with TemporaryDirectory(prefix="rr-obd-proofs-") as workspace:
        template = build_template(Path(workspace) / "template")
        for profile, expected, marker in controls:
            guest = Path(workspace) / profile

            def approve(preview, public_key):
                claim = json.loads(preview)
                if expected is None or public_key.decode("ascii") != issuer.public_hex:
                    raise RuntimeError("Unexpected preview or issuer.")
                if (claim["idle"], claim["moving"]) != expected:
                    raise RuntimeError("Wrong result for bench profile " + profile)
                if profile == "late-reply":
                    # Keep the guest open long enough for the timed-out prompt to arrive.
                    time.sleep(0.7)
                return True

            try:
                result = review_native(guest, qemu, None, approve, issuer.seed, ticket, profile, image=template)
            except ValueError:
                if expected is not None:
                    raise
            else:
                if expected is None or result is None:
                    raise RuntimeError("Unexpected issuance for bench profile " + profile)
                issuer.verify_receipt(result)
                if json.loads(result)["claim"]["source"] != BENCH_SOURCE:
                    raise RuntimeError("The receipt lost its bench source.")
            lines = (guest / "serial.log").read_bytes().splitlines()
            lines = [line.lstrip(b"\x11\x13") for line in lines]
            proof = [line for line in lines if line.startswith(b"RR_")]
            if marker not in proof or (guest / "recording.csv").exists():
                raise RuntimeError("Incomplete native evidence for bench profile " + profile)
            context_changes = [line for line in proof if line.startswith(b"RR_CAPTURE_CONTEXT_CHANGED ")]
            expected_changes = [b"RR_CAPTURE_CONTEXT_CHANGED 1"] if profile == "motion-change" else []
            if context_changes != expected_changes:
                raise RuntimeError("Unexpected motion transition handling in " + profile)
            if expected is None:
                if any(line.startswith(b"RR_RECEIPT ") for line in proof):
                    raise RuntimeError("The guest issued after adapter setup failed.")
            elif b"RR_CAPTURE_ACCESS adapter_denied" not in proof:
                raise RuntimeError("The exporter access check is missing.")
            outcome = "no receipt" if expected is None else f"idle={expected[0]}, moving={expected[1]}"
            summary = f"{profile}: {outcome}"
            traces.append(summary.encode("ascii") + b"\n" + b"\n".join(proof) + b"\n")
            print(f"Verified {summary}.", flush=True)
    return b"\n".join(traces)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    evidence = verify(args.qemu.resolve(strict=True))
    if args.proof:
        args.proof.write_bytes(evidence)
