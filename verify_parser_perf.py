"""Measure QNX preview latency for published drives and the 4 MiB control."""

import argparse
from hashlib import sha256
import json
from math import ceil
from pathlib import Path
import platform
import re
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
import time

from issuer_store import Issuer
from run_qnx import MAX_RECORDING, build_template, review_native
from shop_request import CURRENT_RECIPE, PUBLISHED_SOURCE, request_document
from verify_requests import load_road_pair


def maximum_recording():
    count = (MAX_RECORDING // 32) - 1
    # Offset most lines from block boundaries while keeping the total exactly 4 MiB.
    header = f"{count}\n".rjust(31).encode("ascii")
    rows = b"".join(f"{tick},800,0,101\n".rjust(32 + (tick == count - 1)).encode("ascii")
                    for tick in range(count))
    return header + rows, count


def measure_review(qemu, guest, image, recording, issuer, request, finding, source=None):
    started = time.monotonic()
    preview_seconds = None

    def approve(preview, public_key):
        nonlocal preview_seconds
        preview_seconds = round(time.monotonic() - started, 3)
        if (public_key != issuer.public_hex.encode("ascii") or
                json.loads(preview)[request["scope"]] != finding):
            raise RuntimeError("The timing control returned an unexpected preview.")
        return True

    receipt = review_native(guest, qemu, recording, approve, issuer.seed, request, image=image, source=source)
    issuer.verify_receipt(receipt)
    timings = re.findall(rb"^RR_EVALUATION_US ([0-9]+)\r?$", (guest / "serial.log").read_bytes(), re.MULTILINE)
    if len(timings) != 1 or preview_seconds is None:
        raise RuntimeError("The QNX guest did not report one measurement and preview.")
    return int(timings[0]), preview_seconds, sha256(receipt).hexdigest()


def verify(qemu, repetitions):
    # Fixed synthetic issuer and ID make the signed bytes comparable across builds.
    seed = sha256(b"Repair Receipt parser benchmark issuer").digest()
    issuer = Issuer(seed)
    request = request_document("idle", "827f8d335769463dbff537dd714187cc", CURRENT_RECIPE)
    largest, samples = maximum_recording()
    if len(largest) != MAX_RECORDING:
        raise RuntimeError("The parser benchmark input is not exactly 4 MiB.")

    with TemporaryDirectory(prefix="rr-parser-proof-") as temporary:
        root = Path(temporary)
        image = build_template(root / "template")
        evaluations, previews = [], []
        signatures = set()
        for index in range(repetitions):
            evaluation, preview, signature = measure_review(qemu, root / f"review-{index}", image, largest,
                                                            issuer, request, "not_observed")
            evaluations.append(evaluation)
            previews.append(preview)
            signatures.add(signature)
            print(f"Run {index + 1}: QNX evaluation {evaluation} us, preview {preview} s.", flush=True)
        if len(signatures) != 1:
            raise RuntimeError("Identical inputs yielded different signed receipts.")

        valid = b"2000\r\n0,800,0,105\r\n1000,800,0,105\r\n2000,800,0,105"
        edge = review_native(root / "crlf", qemu, valid, lambda *_: True, seed, request, image=image)
        issuer.verify_receipt(edge)
        if json.loads(edge)["claim"]["idle"] != "observed":
            raise RuntimeError("CRLF or a final line without a newline changed the finding.")

        def unexpected(*_args):
            raise RuntimeError("Invalid input reached approval.")

        for name, data in (("embedded-nul", valid.replace(b"800", b"800\x00", 1)),
                           ("long-line", valid.replace(b"0,800", b" " * 256 + b"0,800", 1))):
            try:
                review_native(root / name, qemu, data, unexpected, seed, request, image=image)
            except ValueError as error:
                if "QNX rejected the recording" not in str(error):
                    raise
            else:
                raise RuntimeError(f"QNX accepted {name} input.")

    return {"input_bytes": len(largest), "input_samples": samples, "qnx_evaluation_us": evaluations,
            "median_qnx_evaluation_us": median(evaluations), "host_to_preview_seconds": previews,
            "signed_receipt_sha256": signatures.pop(), "crlf_and_no_final_newline": True,
            "embedded_nul_and_long_line_rejected": True}


def distribution(samples):
    ordered = sorted(samples)
    return {"samples": samples, "median": round(median(ordered), 3),
            "p95": ordered[ceil(0.95 * len(ordered)) - 1], "max": ordered[-1]}


def verify_preview_latency(qemu, repetitions, roads):
    # A shared test issuer and request make the published-drive receipts comparable.
    issuer = Issuer(sha256(b"Repair Receipt parser benchmark issuer").digest())
    road_request = request_document("idle", "827f8d335769463dbff537dd714187cc", CURRENT_RECIPE, 95)
    limit_request = request_document("idle", "827f8d335769463dbff537dd714187cc", CURRENT_RECIPE)
    maximum, _ = maximum_recording()
    if len(maximum) != MAX_RECORDING:
        raise RuntimeError("The parser benchmark input is not exactly 4 MiB.")
    workloads = [(name, recording, road_request, "observed", PUBLISHED_SOURCE)
                 for name, recording, _ in load_road_pair(roads)]
    workloads.append(("synthetic-4-mib", maximum, limit_request, "not_observed", None))
    samples = {name: [] for name, *_ in workloads}
    with TemporaryDirectory(prefix="rr-preview-latency-") as temporary:
        root = Path(temporary)
        started = time.monotonic()
        image = build_template(root / "template")
        preparation = round(time.monotonic() - started, 3)
        for count in range(repetitions):
            offset = count % len(workloads)
            for name, recording, request, finding, source in workloads[offset:] + workloads[:offset]:
                with TemporaryDirectory(prefix="trial-", dir=root) as run:
                    measurement = measure_review(qemu, Path(run) / "guest", image, recording,
                                                 issuer, request, finding, source)
                samples[name].append(measurement)
            print(f"Verified all three previews for round {count + 1} of {repetitions}.", flush=True)
    profiles = []
    for name, recording, _, _, _ in workloads:
        evaluations, previews, digests = zip(*samples[name], strict=True)
        if len(set(digests)) != 1:
            raise RuntimeError(f"Repeated previews for {name} produced different signed receipts.")
        profiles.append({
            "recording": name, "normalized_bytes": len(recording),
            "normalized_sha256": sha256(recording).hexdigest(),
            "normalized_rows": len(recording.splitlines()) - 1,
            "native_evaluation_us": distribution(list(evaluations)),
            "host_to_preview_seconds": distribution(list(previews)),
            "signed_receipt_sha256": digests[0],
        })
    if profiles[0]["signed_receipt_sha256"] != profiles[1]["signed_receipt_sha256"]:
        raise RuntimeError("The two published drives did not produce the same signed idle receipt.")
    version = subprocess.run([qemu, "--version"], text=True, capture_output=True, check=True, timeout=5)
    return {
        "host": f"{platform.system()} {platform.machine()}",
        "qemu": version.stdout.splitlines()[0],
        "guest": "QNX 8.0 x86-64",
        "runs_per_workload": repetitions,
        "template_preparation_seconds": preparation,
        "percentile_method": "nearest rank",
        "measurement": "Prepared template with a fresh guest per trial. Host timing includes encrypted staging and boot. "
                       "Browser import and UI polling are outside host timing.",
        "profiles": profiles,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--road-pair", type=Path, nargs=2, metavar=("FIRST_DRIVE", "SECOND_DRIVE"),
                        help="measure the documented normalized road pair and the 4 MiB control")
    parser.add_argument("--runs", type=int, help="number of runs per input (5 by default, 20 with --road-pair)")
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    runs = args.runs if args.runs is not None else (20 if args.road_pair else 5)
    if runs < 1:
        parser.error("Use at least one measurement.")
    qemu = args.qemu.resolve(strict=True)
    profile = verify_preview_latency(qemu, runs, args.road_pair) if args.road_pair else verify(qemu, runs)
    result = json.dumps(profile, indent=2) + "\n"
    print(result, end="")
    if args.proof:
        args.proof.write_text(result, encoding="utf-8")
