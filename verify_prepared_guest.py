"""Compare full-build and prepared QNX reviews and verify input isolation."""

import argparse
from hashlib import sha256
import json
import mmap
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time
from unittest.mock import patch

from issuer_store import Issuer
from run_qnx import ROOT, build_template, review_native, seal_recording
from shop_request import CURRENT_RECIPE, DEMO_SOURCE, UPLOADED_SOURCE, guest_bytes


def digest(path):
    sha = sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def confirm_absent(paths, markers):
    for path in paths:
        if path.stat().st_size == 0:
            continue
        with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if any(data.find(marker) != -1 for marker in markers):
                raise RuntimeError(f"Sensitive input appeared in {path.name}.")


def verify(qemu):
    seed = secrets.token_bytes(32)
    issuer = Issuer(seed)
    request = {"format": "repair-receipt-request/v1", "recipe": CURRENT_RECIPE,
               "scope": "idle", "id": secrets.token_hex(16)}
    other = {**request, "id": secrets.token_hex(16), "scope": "moving"}
    fixture = ROOT / "fixtures" / "trip-a.csv"
    alternative = ROOT / "fixtures" / "moving.csv"
    with TemporaryDirectory(prefix="rr-prepared-proof-") as tmp:
        workspace = Path(tmp)
        stage_keys = []

        def capture_stage(recording, source):
            sealed, key = seal_recording(recording, source)
            stage_keys.append(key)
            return sealed, key

        def run(name, recording, ticket, image=None, source=None):
            start = time.monotonic()
            shown = None
            private_preview = None
            guest = workspace / name

            def approve(preview, public_key):
                nonlocal shown, private_preview
                shown = time.monotonic() - start
                if public_key.decode("ascii") != issuer.public_hex:
                    raise RuntimeError("Unexpected issuer from QNX.")
                if json.loads(preview)["request"] != ticket["id"]:
                    raise RuntimeError("Review contained input from a different job.")
                private_preview = preview
                return True

            with patch("run_qnx.seal_recording", side_effect=capture_stage):
                receipt = review_native(guest, qemu, recording, approve, seed, ticket, image=image, source=source)
            issuer.verify_receipt(receipt)
            serial = (guest / "serial.log").read_bytes()
            if image and b"RR_JOB_DISK_BOUNDARY raw_device_denied" not in serial:
                raise RuntimeError("Missing job disk access check.")
            if b"RR_RECORDING_AUTHENTICATED" not in serial or b"RR_PLAINTEXT_BOUNDARY no_staged_file" not in serial:
                raise RuntimeError("Missing native private recording checks.")
            if (private_preview is None or b"RR_PREVIEW [private preview]" not in serial or
                    b"RR_RECEIPT import [signed receipt]" not in serial):
                raise RuntimeError("The diagnostic log did not contain the redacted review markers.")
            confirm_absent([path for path in guest.rglob("*") if path.is_file()],
                           [private_preview, receipt, issuer.public_hex.encode("ascii")])
            print(f"{name} preview in {shown:.2f} seconds.", flush=True)
            return receipt, shown

        cold, cold_wait = run("full_build", fixture, request)
        start = time.monotonic()
        template = build_template(workspace / "template")
        preparation = time.monotonic() - start
        artifacts = [template / "output" / name for name in ("ifs.bin", "disk-qemu.vmdk", "disk-qemu")]
        before = [digest(path) for path in artifacts]
        warm, warm_wait = run("prepared_same_request", fixture, request, template)
        alternate, alternate_wait = run("prepared_separate_request", alternative, other, template)
        largest = workspace / "maximum.csv"
        with largest.open("wb") as output:
            output.write(b"131071\n".rjust(32, b" "))
            for timestamp in range(131071):
                output.write(f"{timestamp},800,0,101\n".encode("ascii").rjust(32, b" "))
        if largest.stat().st_size != 4 * 1024 * 1024:
            raise RuntimeError("Maximum-size recording has the wrong length.")
        maximum, maximum_wait = run("prepared_maximum_input", largest, request, template, UPLOADED_SOURCE)
        maximum_claim = json.loads(maximum)["claim"]
        if maximum_claim["idle"] != "not_observed" or maximum_claim.get("source") != UPLOADED_SOURCE:
            raise RuntimeError("QNX did not complete the maximum-size uploaded recording with its source.")

        if cold != warm or alternate == warm:
            raise RuntimeError("Prepared review changed the expected receipt.")
        if before != [digest(path) for path in artifacts]:
            raise RuntimeError("A guest modified the shared image.")
        names = ("prepared_same_request", "prepared_separate_request", "prepared_maximum_input")
        tokens = [(workspace / name / "boot-token").read_bytes() for name in names]
        if len(set(tokens)) != len(tokens):
            raise RuntimeError("Prepared jobs shared a boot token.")
        if len(stage_keys) != 4 or len(set(stage_keys)) != 4:
            raise RuntimeError("Recordings shared an encryption key.")
        cold_sealed = (workspace / "full_build" / "import.aesgcm").read_bytes()
        warm_sealed = (workspace / "prepared_same_request" / "import.aesgcm").read_bytes()
        if cold_sealed == warm_sealed:
            raise RuntimeError("Encrypting the same recording twice yielded identical ciphertext.")
        for name, original in zip(("full_build", *names), (fixture, fixture, alternative, largest)):
            guest = workspace / name
            with original.open("rb") as source:
                marker = source.read(4096)
            staged = [path for path in guest.rglob("*") if path.is_file()]
            confirm_absent(staged, [marker, seed, seed.hex().encode(), *stage_keys,
                                    *(key.hex().encode() for key in stage_keys)])
        confirm_absent(artifacts, [seed, *tokens, guest_bytes(request), guest_bytes(other),
                                   fixture.read_bytes(), alternative.read_bytes()])

        def unexpected_preview(*_args):
            raise RuntimeError("A corrupted recording reached the approval screen.")

        # The AES-GCM packet starts with a 12-byte nonce, then the encrypted source marker for a sourced CSV.
        for name, byte_index, source in (("corrupted_tag", -1, None), ("corrupted_source_byte", 12, DEMO_SOURCE)):
            def corrupt(recording, recording_source):
                sealed, key = seal_recording(recording, recording_source)
                ciphertext = bytearray(sealed)
                ciphertext[byte_index] ^= 1
                return bytes(ciphertext), key

            corrupted = workspace / name
            with patch("run_qnx.seal_recording", side_effect=corrupt):
                try:
                    review_native(corrupted, qemu, fixture, unexpected_preview, seed, request, image=template,
                                  source=source)
                except RuntimeError as error:
                    if str(error) != "QNX rejected the sealed recording before review.":
                        raise
                else:
                    raise RuntimeError("QNX accepted altered recording bytes.")
            if b"RR_INVALID recording_authentication_failed" not in (corrupted / "serial.log").read_bytes():
                raise RuntimeError("Missing native authentication refusal.")
        return {
            "template_build_seconds": round(preparation, 3),
            "full_build_to_preview_seconds": round(cold_wait, 3),
            "prepared_to_preview_seconds": round(warm_wait, 3),
            "second_prepared_to_preview_seconds": round(alternate_wait, 3),
            "maximum_input_to_preview_seconds": round(maximum_wait, 3),
            "maximum_input_bytes": largest.stat().st_size,
            "maximum_input_source_verified": True,
            "private_job_disk_bytes": (workspace / "prepared_same_request" / "job.qnx6").stat().st_size,
            "same_signed_receipt": True,
            "shared_image_unchanged": True,
            "shared_image_sampled_inputs_absent": True,
            "job_disk_access_denied": True,
            "distinct_job_boot_tokens": True,
            "staged_plaintext_and_keys_absent": True,
            "private_preview_and_receipt_absent_from_guest_workspace": True,
            "distinct_recording_keys": True,
            "native_rejected_corrupted_tag_before_preview": True,
            "native_rejected_altered_source_before_preview": True,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    result = json.dumps(verify(args.qemu.resolve(strict=True)), indent=2)
    print(result)
    if args.proof:
        args.proof.write_bytes((result + "\n").encode("utf-8"))
