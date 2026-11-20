"""Verify that native receipt export requires both driver consent and the QNX channel grant."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native
from shop_request import CURRENT_RECIPE, DEMO_SOURCE, request_document


EXPORT_GRANT = "allow receipt_export_t receipt_owner_t:channel connect;"
EXPORT_DENIAL = b"RR_FAIL connect to receipt channel errno=1"


def compile_template(workspace, policy):
    source = workspace.with_suffix(".conf")
    binary = workspace.with_suffix(".bin")
    source.write_text(policy, encoding="utf-8")
    subprocess.run(["secpolcompile", "-o", str(binary), str(source)], check=True, timeout=30)
    return build_template(workspace, policy_binary=binary)


def without_export_grant(standard):
    lines = standard.splitlines(keepends=True)
    restricted_lines = [line for line in lines if line.rstrip("\n") != EXPORT_GRANT]
    if len(lines) - len(restricted_lines) != 1:
        raise ValueError("The standard policy must contain exactly one exporter channel grant.")
    return "".join(restricted_lines)


def verify_export_denial(workspace, approve):
    try:
        approve()
    except RuntimeError as error:
        if "QNX failed to complete review" not in str(error):
            raise
    else:
        raise RuntimeError("Removing the channel grant did not stop receipt export.")

    trace = [line.lstrip(b"\x11\x13") for line in (workspace / "serial.log").read_bytes().splitlines()]
    if trace.count(EXPORT_DENIAL) != 1 or any(line.startswith(b"RR_RECEIPT ") for line in trace):
        raise RuntimeError("The restricted guest did not show the expected channel denial without a receipt.")
    if b"RR_PREVIEW [private preview]" not in trace[:trace.index(EXPORT_DENIAL)]:
        raise RuntimeError("The channel denial occurred before the native review preview.")


def verify(qemu):
    standard = (ROOT / "policy.conf").read_text(encoding="utf-8")
    restricted = without_export_grant(standard)

    executable = ROOT / "build/repair-receipt"
    executable_digest = sha256(executable.read_bytes()).hexdigest()
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    ticket = request_document("idle", secrets.token_hex(16), CURRENT_RECIPE)
    recording = (ROOT / "fixtures/trip-a.csv").read_bytes()
    expected = {"recipe": CURRENT_RECIPE, "source": DEMO_SOURCE, "request": ticket["id"],
                "scope": "idle", "idle": "observed"}

    with TemporaryDirectory(prefix="rr-native-policy-") as folder:
        scratch = Path(folder)
        control = compile_template(scratch / "control-image", standard)
        denied_image = compile_template(scratch / "restricted-image", restricted)

        decisions = []

        def trial(name, image, share):
            def consent(preview, key):
                if json.loads(preview) != expected or key != issuer.public_hex.encode("ascii"):
                    raise ValueError(f"Unexpected native preview or issuer in {name}.")
                decisions.append((name, share))
                return share

            return review_native(scratch / name, qemu, recording, consent, seed, ticket, image=image,
                                 source=DEMO_SOURCE)

        verify_export_denial(scratch / "policy-denied", lambda: trial("policy-denied", denied_image, True))

        if trial("consent-declined", control, False) is not None:
            raise RuntimeError("The standard policy emitted a receipt after the driver declined.")
        signed = trial("export-approved", control, True)
        if signed is None:
            raise RuntimeError("The standard policy withheld export after the driver approved it.")
        issuer.verify_receipt(signed)
        if json.loads(signed)["claim"] != expected:
            raise RuntimeError("The standard policy returned a different finding from the approved preview.")
        if decisions != [("policy-denied", True), ("consent-declined", False), ("export-approved", True)]:
            raise RuntimeError("A native trial did not complete its intended consent step.")
        if sha256(executable.read_bytes()).hexdigest() != executable_digest:
            raise RuntimeError("The guest executable changed during the experiment.")

    return {
        "platform": "QNX SDP 8.0 x86-64 guest on QEMU",
        "guest_executable_sha256": executable_digest,
        "same_recording_request_and_issuer": True,
        "signed_input_type": DEMO_SOURCE,
        "grant_removed": EXPORT_GRANT,
        "approved_preview_before_denial": True,
        "export_denial": EXPORT_DENIAL.decode("ascii"),
        "receipt_emitted_without_grant": False,
        "receipt_emitted_after_decline": False,
        "receipt_verified_with_grant_and_approval": True,
        "raw_channel_file_disk_and_vault_memory_denied_with_grant": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.qemu.resolve(strict=True)), indent=2))
