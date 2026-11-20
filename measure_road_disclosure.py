"""Measure what the shop receives for the two published road examples."""

import argparse
import csv
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from shop_register import check_receipt, read_receipt
from shop_request import PUBLISHED_SOURCE, canonical, parse_request, verification_packet
from verify_requests import KIT_ROAD_PAIR, ROOT

ORIGINAL_SHA256 = (
    "13116c2435977ea6beb1a8940650c9058a75198c81d97e2101f208375e11114c",
    "1bc325937e4421ab88f057a56272589aae1fb4859525b2f872a8e5386953f349",
)
IDLE_CLAIM_FIELDS = {"recipe", "source", "request", "scope", "thresholdC", "idle"}


def measure(recordings):
    evidence = json.loads((ROOT / "replay/qnx-road-scope-receipts.json").read_bytes())
    key = bytes.fromhex(evidence["issuer"]["key"])
    fingerprint = sha256(key).hexdigest()
    if fingerprint != evidence["issuer"]["fingerprint"]:
        raise ValueError("The archived issuer fingerprint does not match its public key.")
    request = parse_request(canonical(evidence["requests"]["idle"]))
    first, second = evidence["receipts"]["idle"]
    claim = check_receipt(first, read_receipt(first), request, key)
    if (first != second or set(claim) != IDLE_CLAIM_FIELDS or claim["scope"] != "idle" or
            claim["source"] != PUBLISHED_SOURCE or claim["idle"] != "observed"):
        raise ValueError("The archived receipts do not support the paired idle example.")
    packet = canonical(verification_packet(request, first, fingerprint)).encode("ascii")
    measurements = []
    with TemporaryDirectory(prefix="rr-road-disclosure-") as folder:
        temporary = Path(folder)
        for index, (path, (name, expected_normalized), expected_original) in enumerate(
                zip(recordings, KIT_ROAD_PAIR, ORIGINAL_SHA256, strict=True)):
            raw = path.read_bytes()
            original_digest = sha256(raw).hexdigest()
            if original_digest != expected_original:
                raise ValueError(f"Use the unchanged published file {name}.")
            reader = csv.reader(StringIO(raw.decode("utf-8-sig"), newline=""))
            columns = next(reader)
            samples = sum(1 for row in reader if row)
            output = temporary / f"{index}.normalized"
            subprocess.run(["node", str(ROOT / "normalize-obd.cjs"), str(path.resolve()), str(output)],
                           stdout=subprocess.DEVNULL, check=True, timeout=30)
            normalized = output.read_bytes()
            normalized_digest = sha256(normalized).hexdigest()
            if normalized_digest != expected_normalized:
                raise ValueError(f"The local import of {name} does not reproduce the archived native input.")
            duration, *rows = normalized.splitlines()
            measurements.append({
                "name": name,
                "original_csv": {"bytes": len(raw), "sha256": original_digest,
                                 "timestamped_rows": samples, "vehicle_signals": len(columns) - 1},
                "normalized_qnx_input": {"bytes": len(normalized), "sha256": normalized_digest,
                                         "duration_ms": int(duration), "rows": len(rows)},
            })
    return {
        "dataset": "Marc Weber, Automotive OBD-II Dataset (CC BY 4.0)",
        "source": "https://publikationen.bibliothek.kit.edu/1000085073",
        "recordings": measurements,
        "shared_idle_reply": {
            "test_threshold_c": request["thresholdC"],
            "signed_receipt_bytes": len(first.encode("ascii")),
            "signed_claim_fields": sorted(claim),
            "verification_packet_bytes": len(packet),
            "verification_packet_sha256": sha256(packet).hexdigest(),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recordings", type=Path, nargs=2, metavar="CSV")
    parser.add_argument("--proof", type=Path, help="write the measured disclosure report")
    args = parser.parse_args()
    try:
        report = json.dumps(measure(args.recordings), indent=2) + "\n"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Could not measure the road example. {error}\n")
    if args.proof:
        args.proof.write_bytes(report.encode("utf-8"))
    print(report, end="")
