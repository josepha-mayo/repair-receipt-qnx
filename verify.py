"""Verify a complete native run and prepare its self-contained replay."""

import argparse
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = {
    "trip-a": ("observed", "not_observed"),
    "trip-b": ("observed", "not_observed"),
    "moving": ("not_observed", "observed"),
    "gap": ("insufficient_evidence", "insufficient_evidence"),
    "kit-obd": ("insufficient_evidence", "not_observed"),
    "scope-control": ("observed", "observed"),
}
BOUNDARY = b"RR_BOUNDARY raw_channel_denied raw_file_denied"


def verify(trace):
    lines = [line for line in trace.splitlines() if line.startswith(b"RR_")]
    expected = [
        b"RR_PLATFORM QNX 8.0.0",
        b"RR_CONTROL authorized_raw_read",
        b"RR_UNAPPROVED refused",
        BOUNDARY,
    ]
    evidence = {}
    for case, (idle, moving) in CASES.items():
        receipt = json.dumps(
            {"recipe": "coolant-context-demo/v1", "idle": idle, "moving": moving},
            separators=(",", ":"),
        )
        expected.extend([f"RR_RECEIPT {case} {receipt}".encode("ascii"), BOUNDARY])
        fixture = (ROOT / "fixtures" / f"{case}.csv").read_bytes()
        rows = list(csv.reader(fixture.decode("ascii").splitlines()))
        evidence[case] = {
            "receipt": receipt,
            "sha256": hashlib.sha256(receipt.encode("ascii")).hexdigest(),
            "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
            "duration_ms": int(rows[0][0]),
            "samples": [[int(value) for value in row] for row in rows[1:]],
        }
    expected.extend([b"RR_DONE", b"RR_EXIT=0"])
    if lines != expected:
        raise ValueError("Native trace is incomplete or differs from the expected outcomes.")
    if evidence["trip-a"]["fixture_sha256"] == evidence["trip-b"]["fixture_sha256"]:
        raise ValueError("The privacy controls must use different fixtures.")
    return b"\n".join(lines) + b"\n", evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    trace, evidence = verify(args.trace.read_bytes())
    if args.output:
        args.output.mkdir(exist_ok=True, parents=True)
        (args.output / "qnx-proof.txt").write_bytes(trace)
        template = (ROOT / "viewer.html").read_text(encoding="utf-8")
        replay = template.replace("__VERIFIED_RUN__", json.dumps(evidence, separators=(",", ":")))
        (args.output / "repair-receipt.html").write_text(replay, encoding="utf-8")
    print(f"QNX proof verified: {len(CASES) + 1} raw-access denials, one consent refusal, {len(CASES)} receipts.")
    print("Distinct recordings A and B yield identical bytes. Moving and incomplete controls differ.")


if __name__ == "__main__":
    main()
