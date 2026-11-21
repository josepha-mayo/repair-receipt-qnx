"""Measure answer coverage across the published KIT road archive using QNX."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import secrets
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native
from shop_request import CURRENT_RECIPE, DEFAULT_THRESHOLD_C, SCOPES, UPLOADED_SOURCE, matches_claim, request_document


THRESHOLDS = (95, DEFAULT_THRESHOLD_C)
CONDITIONS = SCOPES["both"][1]
OUTCOMES = ("observed", "not_observed", "insufficient_evidence")


def prepare_inputs(archive, directory):
    with ZipFile(archive) as bundle:
        members = sorted(name for name in bundle.namelist() if name.lower().endswith(".csv"))
        names = [PurePosixPath(name).name for name in members]
        if len(names) != 81 or len(set(names)) != len(names):
            raise ValueError("Choose the published KIT Automotive OBD-II ZIP with 81 distinct CSV recordings.")
        for index, (member, name) in enumerate(zip(members, names)):
            raw = bundle.read(member)
            source = directory / "input.csv"
            projection = directory / f"{index}.csv"
            source.write_bytes(raw)
            subprocess.run(["node", str(ROOT / "normalize-obd.cjs"), str(source), str(projection)],
                           check=True, stdout=subprocess.DEVNULL)
            yield name, projection, sha256(raw).hexdigest(), sha256(projection.read_bytes()).hexdigest()


def run_recording(item, qemu, template, issuer, directory):
    name, projection, original_hash, normalized_hash = item
    findings = {}
    for threshold in THRESHOLDS:
        request = request_document("both", secrets.token_hex(16), CURRENT_RECIPE, threshold)

        def approve(preview, key):
            if key.decode("ascii") != issuer.public_hex or not matches_claim(preview, request, UPLOADED_SOURCE):
                raise RuntimeError(f"Unexpected QNX preview for {name} at {threshold} °C.")
            return True

        with TemporaryDirectory(prefix="guest-", dir=directory) as tmp:
            receipt = review_native(Path(tmp) / "review", qemu, projection, approve, issuer.seed, request,
                                    image=template, source=UPLOADED_SOURCE)
        issuer.verify_receipt(receipt)
        record = json.loads(receipt)
        if record["format"] != "repair-receipt/v5":
            raise RuntimeError(f"Unexpected signed receipt format for {name}.")
        findings[str(threshold)] = {condition: record["claim"][condition] for condition in CONDITIONS}
    lower, higher = [findings[str(threshold)] for threshold in THRESHOLDS]
    for condition in CONDITIONS:
        if lower[condition] != "observed" and higher[condition] != lower[condition]:
            raise RuntimeError(f"Raising the threshold changed a negative or unknown result for {name}.")
    return {"recording": name, "sourceSha256": original_hash, "normalizedSha256": normalized_hash,
            "findings": findings}


def summarize(rows, threshold):
    trials = [row["findings"][str(threshold)] for row in rows]
    per_condition = {}
    for condition in CONDITIONS:
        counts = Counter(trial[condition] for trial in trials)
        per_condition[condition] = {outcome: counts[outcome] for outcome in OUTCOMES}
    answered = Counter(sum(trial[condition] != "insufficient_evidence" for condition in CONDITIONS)
                       for trial in trials)
    return {"byCondition": per_condition, "answerableConditions": {
        "both": answered[2], "one": answered[1], "neither": answered[0],
    }}


def verify(archive, qemu, jobs):
    issuer = Issuer(secrets.token_bytes(32))
    with TemporaryDirectory(prefix="rr-road-corpus-") as tmp:
        directory = Path(tmp)
        inputs = list(prepare_inputs(archive, directory))
        print(f"Normalized {len(inputs)} recordings. Building the shared QNX guest template.", flush=True)
        template = build_template(directory / "template")
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            tasks = [pool.submit(run_recording, item, qemu, template, issuer, directory) for item in inputs]
            rows = []
            for task in tasks:
                rows.append(task.result())
                if len(rows) % 10 == 0 or len(rows) == len(inputs):
                    print(f"Verified {len(rows)}/{len(inputs)} recordings at both thresholds.", flush=True)
    return {
        "dataset": "Marc Weber, Automotive OBD-II Dataset (CC BY 4.0)",
        "source": "https://publikationen.bibliothek.kit.edu/1000085073",
        "archiveSha256": sha256(archive.read_bytes()).hexdigest(),
        "platform": "QNX SDP 8.0 x86-64 on QEMU",
        "recipe": CURRENT_RECIPE,
        "scope": "both",
        "signedInputType": UPLOADED_SOURCE,
        "recordings": len(rows),
        "signaturesVerified": len(rows) * len(THRESHOLDS),
        "thresholdsC": {str(threshold): summarize(rows, threshold) for threshold in THRESHOLDS},
        "trials": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--jobs", type=int, default=2, choices=range(1, 9))
    args = parser.parse_args()
    report = verify(args.archive.resolve(strict=True), args.qemu.resolve(strict=True), args.jobs)
    if args.proof:
        with args.proof.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report["thresholdsC"], indent=2))
