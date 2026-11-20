"""Measure native QNX CSV evaluation at the 4 MiB input limit."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
from statistics import median
from tempfile import TemporaryDirectory
import time

from issuer_store import Issuer
from run_qnx import MAX_RECORDING, build_template, review_native
from shop_request import CURRENT_RECIPE, request_document


def maximum_recording():
    count = (MAX_RECORDING // 32) - 1
    # Offset most lines from block boundaries while keeping the total exactly 4 MiB.
    header = f"{count}\n".rjust(31).encode("ascii")
    rows = b"".join(f"{tick},800,0,101\n".rjust(32 + (tick == count - 1)).encode("ascii")
                    for tick in range(count))
    return header + rows, count


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
            guest = root / f"review-{index}"
            started = time.monotonic()

            def approve(claim, _issuer):
                previews.append(round(time.monotonic() - started, 3))
                if json.loads(claim)["idle"] != "not_observed":
                    raise RuntimeError("The input limit control returned an unexpected finding.")
                return True

            receipt = review_native(guest, qemu, largest, approve, seed, request, image=image)
            issuer.verify_receipt(receipt)
            timings = re.findall(rb"^RR_EVALUATION_US ([0-9]+)\r?$", (guest / "serial.log").read_bytes(), re.MULTILINE)
            if len(timings) != 1:
                raise RuntimeError("The QNX guest did not report a single parser measurement.")
            evaluations.append(int(timings[0]))
            signatures.add(sha256(receipt).hexdigest())
            print(f"Run {index + 1}: QNX evaluation {evaluations[-1]} us, preview {previews[-1]} s.", flush=True)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("Use at least one measurement.")
    result = json.dumps(verify(args.qemu.resolve(strict=True), args.runs), indent=2) + "\n"
    print(result, end="")
    if args.proof:
        args.proof.write_text(result, encoding="utf-8")
