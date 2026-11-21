"""Run the QNX scoped disclosure controls without a browser."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native
from shop_request import CURRENT_RECIPE, DEMO_SOURCE, PUBLISHED_SOURCE, canonical, request_document, verification_packet
from verify_policy import compile_template, verify_export_denial, without_export_grant


KIT_ROAD_PAIR = (
    ("2017-07-26_Seat_Leon_RT_S_Stau.csv", "c8cedc5bbeea1a87a36f1e44899956f2b99e6943326d66d17f68af171a5af83d"),
    ("2017-07-27_Seat_Leon_KA_KA_2_Normal.csv", "6bbd7898d0ba00512387b93677797738474a75f3c5553d89fdc9fa41623516b3"),
)


def verify(qemu, *, check_export_grant=False):
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    issuer_key = issuer.public_hex.encode("ascii")
    tickets = {scope: request_document(scope, secrets.token_hex(16), CURRENT_RECIPE)
               for scope in ("idle", "moving")}
    results = {}
    controls = (
        ("trip_a_at_idle", "trip-a", "idle", "observed", True),
        ("trip_c_at_idle", "scope-control", "idle", "observed", True),
        ("trip_a_while_moving", "trip-a", "moving", "not_observed", True),
        ("trip_c_while_moving", "scope-control", "moving", "observed", True),
        ("declined", "gap", "idle", "insufficient_evidence", False),
    )
    with TemporaryDirectory(prefix="repair-receipt-proof-") as temporary:
        root = Path(temporary)
        if check_export_grant:
            policy = (ROOT / "policy.conf").read_text(encoding="utf-8")
            restricted = without_export_grant(policy)
            executable = ROOT / "build/repair-receipt"
            executable_digest = sha256(executable.read_bytes()).hexdigest()
            template = compile_template(root / "template", policy)
            denied_image = compile_template(root / "restricted", restricted)
        else:
            template = build_template(root / "template")
        for name, fixture, scope, finding, share in controls:
            ticket = tickets[scope]
            expected = {"recipe": CURRENT_RECIPE, "source": DEMO_SOURCE, "request": ticket["id"],
                        "scope": scope, scope: finding}

            def decide(preview, key):
                if json.loads(preview) != expected or key != issuer_key:
                    raise ValueError("QNX preview or issuer did not match the control.")
                return share

            coverage = {}
            recording = (ROOT / "fixtures" / f"{fixture}.csv").read_bytes()
            body = review_native(root / name, qemu, recording,
                                 decide, seed, ticket, image=template, source=DEMO_SOURCE, on_coverage=coverage.update)
            if (body is not None) != share:
                raise RuntimeError(f"Incorrect receipt decision for {name}.")
            if body is not None:
                issuer.verify_receipt(body)
            if coverage != ({} if share else {"idle": 1}):
                raise RuntimeError(f"Unexpected private recording guidance for {name}.")
            if coverage:
                events = (root / name / "serial.log").read_bytes().splitlines()
                if [line for line in events if line.startswith(b"RR_COVERAGE ")] != [
                        b"RR_COVERAGE [driver-only guidance]"]:
                    raise RuntimeError("Driver guidance entered the diagnostic log without redaction.")
            results[name] = body
            if check_export_grant and name == "trip_a_at_idle":
                denied = root / "policy-denied"
                verify_export_denial(denied, lambda: review_native(
                    denied, qemu, recording, decide, seed, ticket, image=denied_image, source=DEMO_SOURCE))
        if check_export_grant and sha256(executable.read_bytes()).hexdigest() != executable_digest:
            raise RuntimeError("The guest executable changed during the experiment.")
    if results["trip_a_at_idle"] != results["trip_c_at_idle"]:
        raise RuntimeError("Withheld driving findings changed the signed idle receipt.")
    if results["trip_a_while_moving"] == results["trip_c_while_moving"]:
        raise RuntimeError("The independently requested driving finding did not change the signed receipt.")
    return {name: sha256(body).hexdigest() if body is not None else None for name, body in results.items()}


def scoped_recording(scope, finding, hot_outside_scope):
    selected_speed = 0 if scope == "idle" else 40
    other_speed = 40 if scope == "idle" else 0
    selected_count = 2 if finding == "insufficient_evidence" else 3
    selected_temp = 106 if finding == "observed" else 99
    other_temp = 112 if hot_outside_scope else 97
    other_rpm = 1600 if hot_outside_scope else 1100
    rows = [f"{index * 1000},800,{selected_speed},{selected_temp}\n" for index in range(selected_count)]
    rows.extend(f"{index * 1000},{other_rpm},{other_speed},{other_temp}\n" for index in range(selected_count, 6))
    return ("6000\n" + "".join(rows)).encode("ascii")


def extended_outside_scope(scope, recording):
    selected_speed = 0 if scope == "idle" else 40
    rows = [tuple(map(int, line.split(b","))) for line in recording.splitlines()[1:]]
    selected = [(tick + 4000, rpm, speed, temperature)
                for tick, rpm, speed, temperature in rows if speed == selected_speed]
    last_selected = selected[-1][0]

    def other_sample(tick):
        index = tick // 500
        speed = 5 + index * 7 % 100 if scope == "idle" else 0
        return tick, 700 + index * 61 % 2500, speed, 20 + index * 19 % 115

    before = [other_sample(tick) for tick in range(0, 4000, 500)]
    after = [other_sample(tick) for tick in range(last_selected + 500, last_selected + 26500, 500)]
    extended = [*before, *selected, *after]
    duration = extended[-1][0] + 250
    body = "".join(f"{tick},{rpm},{speed},{temperature}\r\n" for tick, rpm, speed, temperature in extended)
    return (f"{duration}\r\n" + body).encode("ascii")


def missing_sample(recording, time_ms):
    prefix = f"{time_ms},".encode("ascii")
    return b"".join(prefix + b",,\n" if row.startswith(prefix) else row for row in recording.splitlines(keepends=True))


def verify_scope_matrix(qemu):
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    fingerprint = issuer.public_profile()["fingerprint"]
    signed_count = 0
    with TemporaryDirectory(prefix="rr-scope-matrix-") as temporary:
        root = Path(temporary)
        template = build_template(root / "template")

        def review(name, recording, ticket, findings, expected_guidance=None):
            nonlocal signed_count
            expected = {"recipe": CURRENT_RECIPE, "request": ticket["id"], "scope": ticket["scope"], **findings}
            guidance = {}

            def approve(preview, key):
                if json.loads(preview) != expected or key != issuer.public_hex.encode("ascii"):
                    raise ValueError(f"Unexpected preview or issuer in {name}.")
                return True

            guest = root / name
            signed = review_native(guest, qemu, recording, approve, seed, ticket, image=template,
                                   on_coverage=guidance.update)
            issuer.verify_receipt(signed)
            if json.loads(signed)["claim"] != expected:
                raise RuntimeError(f"An unexpected finding entered the signed receipt in {name}.")
            if expected_guidance is not None and guidance != expected_guidance:
                raise RuntimeError(f"Unexpected driver coverage guidance in {name}.")
            log = (guest / "serial.log").read_bytes().splitlines()
            timing = [line for line in log if b"RR_EVALUATION_US " in line]
            if timing != [b"RR_EVALUATION_US [private timing]"]:
                raise RuntimeError(f"The diagnostic log recorded private evaluation timing in {name}.")
            coverage = [line for line in log if b"RR_COVERAGE " in line]
            if coverage != ([b"RR_COVERAGE [driver-only guidance]"] if guidance else []):
                raise RuntimeError(f"The diagnostic log recorded private coverage guidance in {name}.")
            signed_count += 1
            return signed

        pairs = []
        private_reasons = []
        for scope in ("idle", "moving"):
            ticket = request_document(scope, secrets.token_hex(16), CURRENT_RECIPE)
            answers = {}
            for finding in ("observed", "not_observed", "insufficient_evidence"):
                name = f"{scope}-{finding}"
                cool = scoped_recording(scope, finding, False)
                hot = scoped_recording(scope, finding, True)
                inputs = (cool, hot, extended_outside_scope(scope, cool))
                guidance = {scope: 2} if finding == "insufficient_evidence" else {}
                receipts = [review(f"{name}-{index}", recording, ticket, {scope: finding}, guidance)
                            for index, recording in enumerate(inputs)]
                if len(set(receipts)) != 1:
                    raise RuntimeError(f"Out-of-scope changes altered the signed receipt in {name}.")
                packets = [canonical(verification_packet(ticket, receipt.decode("ascii"), fingerprint))
                           for receipt in receipts]
                if len(set(packets)) != 1:
                    raise RuntimeError(f"Out-of-scope changes altered the verification packet in {name}.")
                answers[finding] = receipts[0]
                pairs.append({"scope": scope, "finding": finding, "recordings": len(inputs),
                              "byte_identical_receipts": True, "byte_identical_verification_packets": True})
                print(f"Verified three variants for {scope}: {finding}.", file=sys.stderr, flush=True)

            for underlying, code in (("not_observed", 1), ("insufficient_evidence", 3)):
                data = missing_sample(scoped_recording(scope, underlying, True), 4000)
                changed = review(f"{scope}-guidance-{code}", data, ticket, {scope: "insufficient_evidence"}, {scope: code})
                if changed != answers["insufficient_evidence"]:
                    raise RuntimeError(f"Driver-only coverage details altered the {scope} receipt.")
            private_reasons.append({"scope": scope, "driver_coverage_codes_checked": [1, 2, 3],
                                    "byte_identical_insufficient_evidence_receipts": True})

        both = request_document("both", secrets.token_hex(16), CURRENT_RECIPE)
        for hot, moving in ((False, "not_observed"), (True, "observed")):
            review(f"both-{moving}", scoped_recording("idle", "observed", hot), both,
                   {"idle": "observed", "moving": moving})

        idle = request_document("idle", secrets.token_hex(16), CURRENT_RECIPE)
        positive_gap = missing_sample(scoped_recording("idle", "observed", True), 4000)
        review("gap-observed", positive_gap, idle, {"idle": "observed"}, {})

        def unexpected_preview(*_args):
            raise RuntimeError("An invalid out-of-scope row reached approval.")

        malformed = scoped_recording("idle", "observed", True).replace(b"4000,1600,40,112", b"4000,1600,40,201")
        try:
            review_native(root / "invalid-omitted-row", qemu, malformed, unexpected_preview, seed, idle, image=template)
        except ValueError as error:
            if "QNX rejected the recording" not in str(error):
                raise
        else:
            raise RuntimeError("QNX skipped validation of an out-of-scope row.")

    return {
        "platform": "QNX SDP 8.0 x86-64 guest on QEMU",
        "recipe": CURRENT_RECIPE,
        "signed_receipts_verified": signed_count,
        "paired_checks": pairs,
        "unrequested_variations_checked": ["RPM and temperature", "speed, cadence, duration and line endings"],
        "driver_only_guidance_checks": private_reasons,
        "numeric_evaluation_timing_redacted_from_review_logs": True,
        "both_conditions_control": {"idle": "observed", "moving": ["not_observed", "observed"]},
        "idle_with_unknown_coverage": {"before_gap_not_observed": "insufficient_evidence",
                                       "observed_run_before_gap": "observed"},
        "invalid_out_of_scope_row_rejected_before_preview": True,
    }


def load_road_pair(recordings):
    inputs = []
    for path, (name, expected_digest) in zip(recordings, KIT_ROAD_PAIR, strict=True):
        recording = path.read_bytes()
        digest = sha256(recording).hexdigest()
        if digest != expected_digest:
            raise ValueError(f"Expected the normalized bytes of {name} (SHA-256 {expected_digest}).")
        inputs.append((name, recording, digest))
    return inputs


def verify_road_pair(qemu, recordings, signed_evidence=None):
    """Check the two documented KIT drives with a common idle-only request."""
    inputs = load_road_pair(recordings)
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    threshold = 95
    tickets = {scope: request_document(scope, secrets.token_hex(16), CURRENT_RECIPE, threshold)
               for scope in ("idle", "moving")}
    results = []
    receipts = {scope: [] for scope in tickets}
    with TemporaryDirectory(prefix="repair-receipt-road-proof-") as temporary:
        workspace = Path(temporary)
        image = build_template(workspace / "template")
        for index, (name, recording, digest) in enumerate(inputs):
            moving = ("observed", "insufficient_evidence")[index]
            result = {"recording": name, "normalized_bytes": len(recording), "normalized_sha256": digest}
            for scope, finding in (("idle", "observed"), ("moving", moving)):
                ticket = tickets[scope]

                def approve(preview, key):
                    if key.decode("ascii") != issuer.public_hex or json.loads(preview)[scope] != finding:
                        raise RuntimeError(f"Unexpected {scope} control on {name}.")
                    return True

                signed = review_native(workspace / f"{index}-{scope}", qemu, recording, approve,
                                       seed, ticket, image=image, source=PUBLISHED_SOURCE)
                issuer.verify_receipt(signed)
                result[scope] = finding
                receipts[scope].append(signed.decode("ascii"))
            results.append(result)
    idle_a, idle_b = receipts["idle"]
    moving_a, moving_b = receipts["moving"]
    if idle_a != idle_b or moving_a == moving_b:
        raise RuntimeError("The signed receipts must match at idle and differ while moving.")
    if signed_evidence is not None:
        evidence = json.dumps({
            "issuer": issuer.public_profile(), "requests": tickets, "receipts": receipts,
        }, indent=2) + "\n"
        signed_evidence.write_bytes(evidence.encode("utf-8"))
    return {"dataset": "Marc Weber, Automotive OBD-II Dataset (CC BY 4.0)",
            "source": "https://publikationen.bibliothek.kit.edu/1000085073", "test_threshold_c": threshold,
            "signed_input_type": PUBLISHED_SOURCE,
            "recordings": results, "same_request_and_issuer": True, "byte_identical_idle_receipts": True,
            "different_moving_receipts": True,
            "idle_receipt_bytes": len(idle_a), "idle_receipt_sha256": sha256(idle_a.encode("ascii")).hexdigest()}


def verify_road_sweep(qemu, recordings):
    """Measure scoped output across 90–105 °C on the two documented KIT drives."""
    inputs = load_road_pair(recordings)
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    issuer_key = issuer.public_hex.encode("ascii")

    def approve(_preview, key):
        if key != issuer_key:
            raise RuntimeError("Unexpected issuer in KIT threshold sweep.")
        return True

    thresholds = []
    with TemporaryDirectory(prefix="rr-road-thresholds-") as temporary:
        workspace = Path(temporary)
        image = build_template(workspace / "template")
        for threshold in range(90, 106):
            row = {"threshold_c": threshold}
            for scope in ("idle", "moving"):
                ticket = request_document(scope, secrets.token_hex(16), CURRENT_RECIPE, threshold)
                signed = []
                for index, (_, recording, _) in enumerate(inputs):
                    with TemporaryDirectory(prefix=f"{threshold}-{scope}-{index}-", dir=workspace) as run:
                        receipt = review_native(Path(run) / "guest", qemu, recording, approve, seed, ticket,
                                                image=image, source=PUBLISHED_SOURCE)
                    issuer.verify_receipt(receipt)
                    signed.append(receipt)
                findings = [json.loads(receipt)["claim"][scope] for receipt in signed]
                identical = signed[0] == signed[1]
                if identical != (findings[0] == findings[1]):
                    raise RuntimeError(f"Signed bytes do not agree with the scoped findings at {threshold} C.")
                row[scope] = {"findings": findings, "byte_identical_receipts": identical}
            thresholds.append(row)
            print(f"Verified {threshold} C on both drives and both scopes.", file=sys.stderr, flush=True)

    reference = thresholds[95 - 90]
    if (reference["idle"]["findings"] != ["observed", "observed"] or
            reference["moving"]["findings"] != ["observed", "insufficient_evidence"]):
        raise RuntimeError("The threshold sweep did not reproduce the archived 95 C control.")
    separating = [row["threshold_c"] for row in thresholds
                  if row["idle"]["byte_identical_receipts"] and not row["moving"]["byte_identical_receipts"]]
    return {"platform": "QNX SDP 8.0 x86-64 guest on QEMU",
            "dataset": "Marc Weber, Automotive OBD-II Dataset (CC BY 4.0)",
            "source": "https://publikationen.bibliothek.kit.edu/1000085073",
            "signed_input_type": PUBLISHED_SOURCE,
            "recordings": [{"recording": name, "normalized_sha256": digest} for name, _, digest in inputs],
            "signed_receipts_verified": len(thresholds) * 4,
            "same_idle_and_different_moving_c": separating,
            "thresholds": thresholds}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    controls = parser.add_mutually_exclusive_group()
    controls.add_argument("--road-pair", type=Path, nargs=2, metavar=("FIRST_DRIVE", "SECOND_DRIVE"),
                          help="two normalized KIT recordings listed in the codelab")
    controls.add_argument("--road-sweep", type=Path, nargs=2, metavar=("FIRST_DRIVE", "SECOND_DRIVE"),
                          help="test the documented KIT pair at every whole degree from 90 to 105 Celsius")
    controls.add_argument("--scope-matrix", action="store_true",
                          help="check both scopes, all findings, and coverage controls")
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--signed-evidence", type=Path, help="save the public key, requests and four signed road receipts")
    args = parser.parse_args()
    if args.signed_evidence and not args.road_pair:
        parser.error("--signed-evidence requires --road-pair")
    qemu = args.qemu.resolve(strict=True)
    if args.road_pair:
        report = verify_road_pair(qemu, args.road_pair, args.signed_evidence)
    elif args.road_sweep:
        report = verify_road_sweep(qemu, args.road_sweep)
    elif args.scope_matrix:
        report = verify_scope_matrix(qemu)
    else:
        report = verify(qemu)
    encoded = json.dumps(report, indent=2) + "\n"
    print(encoded, end="")
    if args.proof:
        args.proof.write_bytes(encoded.encode("utf-8"))
